use std::{
    any::Any,
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use quinn::congestion::{Controller, ControllerFactory, ControllerMetrics};
use quinn_proto::RttEstimator;
use tokio::sync::Notify;

const SLOT_COUNT: usize = 5;
const MIN_SAMPLE_BYTES: u64 = 50 * 1200;
const MIN_ACK_RATE: f64 = 0.8;
const MIN_WINDOW: u64 = 10_240;
const QUINN_PACING_WINDOW_FACTOR: f64 = 0.8;

#[derive(Debug)]
pub(crate) struct Hy2CongestionConfig {
    server_limit_bps: u64,
    pending_rates: Mutex<VecDeque<Arc<AtomicU64>>>,
    pending_rates_ready: Notify,
}

impl Hy2CongestionConfig {
    pub(crate) fn new(server_limit_bps: u64) -> Self {
        Self {
            server_limit_bps,
            pending_rates: Mutex::new(VecDeque::new()),
            pending_rates_ready: Notify::new(),
        }
    }

    pub(crate) async fn take_pending_rate(&self) -> Arc<AtomicU64> {
        loop {
            let notified = self.pending_rates_ready.notified();
            if let Some(rate) = self
                .pending_rates
                .lock()
                .expect("congestion rate queue")
                .pop_front()
            {
                return rate;
            }
            notified.await;
        }
    }

    pub(crate) fn negotiated_rate(&self, client_receive_bps: u64) -> u64 {
        match (self.server_limit_bps, client_receive_bps) {
            (_, 0) => 0,
            (0, client) => client,
            (server, client) => server.min(client),
        }
    }
}

impl ControllerFactory for Hy2CongestionConfig {
    fn build(self: Arc<Self>, now: Instant, current_mtu: u16) -> Box<dyn Controller> {
        let rate = Arc::new(AtomicU64::new(0));
        self.pending_rates
            .lock()
            .expect("congestion rate queue")
            .push_back(Arc::clone(&rate));
        self.pending_rates_ready.notify_one();
        let bbr = Arc::new(quinn::congestion::BbrConfig::default()).build(now, current_mtu);
        Box::new(Hy2Controller {
            bbr,
            brutal: BrutalController::new(rate, current_mtu, now),
        })
    }
}

struct Hy2Controller {
    bbr: Box<dyn Controller>,
    brutal: BrutalController,
}

impl Hy2Controller {
    fn use_brutal(&self) -> bool {
        self.brutal.bytes_per_second() > 0
    }
}

impl Controller for Hy2Controller {
    fn on_sent(&mut self, now: Instant, bytes: u64, last_packet_number: u64) {
        if self.use_brutal() {
            self.brutal.on_sent(now, bytes, last_packet_number);
        } else {
            self.bbr.on_sent(now, bytes, last_packet_number);
        }
    }

    fn on_ack(
        &mut self,
        now: Instant,
        sent: Instant,
        bytes: u64,
        app_limited: bool,
        rtt: &RttEstimator,
    ) {
        if self.use_brutal() {
            self.brutal.on_ack(now, sent, bytes, app_limited, rtt);
        } else {
            self.bbr.on_ack(now, sent, bytes, app_limited, rtt);
        }
    }

    fn on_end_acks(
        &mut self,
        now: Instant,
        in_flight: u64,
        app_limited: bool,
        largest_packet_num_acked: Option<u64>,
    ) {
        if self.use_brutal() {
            self.brutal
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        } else {
            self.bbr
                .on_end_acks(now, in_flight, app_limited, largest_packet_num_acked);
        }
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        sent: Instant,
        is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        if self.use_brutal() {
            self.brutal
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        } else {
            self.bbr
                .on_congestion_event(now, sent, is_persistent_congestion, lost_bytes);
        }
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.bbr.on_mtu_update(new_mtu);
        self.brutal.on_mtu_update(new_mtu);
    }

    fn window(&self) -> u64 {
        if self.use_brutal() {
            self.brutal.window()
        } else {
            self.bbr.window()
        }
    }

    fn metrics(&self) -> ControllerMetrics {
        if self.use_brutal() {
            self.brutal.metrics()
        } else {
            self.bbr.metrics()
        }
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(Self {
            bbr: self.bbr.clone_box(),
            brutal: self.brutal.clone(),
        })
    }

    fn initial_window(&self) -> u64 {
        self.bbr.initial_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

struct BrutalController {
    bytes_per_second: Arc<AtomicU64>,
    mtu: u16,
    started: Instant,
    rtt: Duration,
    ack_rate: f64,
    slots: [SampleSlot; SLOT_COUNT],
    cached_rate: AtomicU64,
    cached_window: AtomicU64,
    cached_pacing_rate: AtomicU64,
}

#[derive(Clone, Copy)]
struct SampleSlot {
    second: u64,
    acked_bytes: u64,
    lost_bytes: u64,
}

impl BrutalController {
    fn new(bytes_per_second: Arc<AtomicU64>, mtu: u16, now: Instant) -> Self {
        let controller = Self {
            bytes_per_second,
            mtu,
            started: now,
            rtt: Duration::from_millis(100),
            ack_rate: 1.0,
            slots: [SampleSlot {
                second: u64::MAX,
                acked_bytes: 0,
                lost_bytes: 0,
            }; SLOT_COUNT],
            cached_rate: AtomicU64::new(u64::MAX),
            cached_window: AtomicU64::new(MIN_WINDOW),
            cached_pacing_rate: AtomicU64::new(0),
        };
        controller.refresh_cache(true);
        controller
    }

    fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second.load(Ordering::Relaxed)
    }

    fn record(&mut self, now: Instant, acked_bytes: u64, lost_bytes: u64) {
        let second = now.saturating_duration_since(self.started).as_secs();
        let slot = &mut self.slots[second as usize % SLOT_COUNT];
        if slot.second != second {
            *slot = SampleSlot {
                second,
                acked_bytes: 0,
                lost_bytes: 0,
            };
        }
        slot.acked_bytes = slot.acked_bytes.saturating_add(acked_bytes);
        slot.lost_bytes = slot.lost_bytes.saturating_add(lost_bytes);

        let oldest = second.saturating_sub(SLOT_COUNT as u64);
        let (acked, lost) = self
            .slots
            .iter()
            .filter(|sample| sample.second >= oldest && sample.second <= second)
            .fold((0_u64, 0_u64), |(acked, lost), sample| {
                (
                    acked.saturating_add(sample.acked_bytes),
                    lost.saturating_add(sample.lost_bytes),
                )
            });
        let total = acked.saturating_add(lost);
        self.ack_rate = if total < MIN_SAMPLE_BYTES {
            1.0
        } else {
            (acked as f64 / total as f64).max(MIN_ACK_RATE)
        };
        self.refresh_cache(true);
    }

    fn refresh_cache(&self, force: bool) {
        let rate = self.bytes_per_second();
        if !force && rate == self.cached_rate.load(Ordering::Relaxed) {
            return;
        }
        let target =
            rate as f64 * self.rtt.as_secs_f64() * QUINN_PACING_WINDOW_FACTOR / self.ack_rate;
        self.cached_rate.store(rate, Ordering::Relaxed);
        self.cached_window.store(
            (target as u64).max(MIN_WINDOW).max(u64::from(self.mtu) * 2),
            Ordering::Relaxed,
        );
        self.cached_pacing_rate.store(
            ((rate as f64 / self.ack_rate) * 8.0) as u64,
            Ordering::Relaxed,
        );
    }

    fn target_window(&self) -> u64 {
        self.refresh_cache(false);
        self.cached_window.load(Ordering::Relaxed)
    }
}

impl Controller for BrutalController {
    fn on_ack(
        &mut self,
        now: Instant,
        _sent: Instant,
        bytes: u64,
        _app_limited: bool,
        rtt: &RttEstimator,
    ) {
        self.rtt = rtt.get();
        self.record(now, bytes, 0);
    }

    fn on_congestion_event(
        &mut self,
        now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.record(now, 0, lost_bytes);
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mtu = new_mtu;
        self.refresh_cache(true);
    }

    fn window(&self) -> u64 {
        self.target_window()
    }

    fn metrics(&self) -> ControllerMetrics {
        self.refresh_cache(false);
        let mut metrics = ControllerMetrics::default();
        metrics.congestion_window = self.cached_window.load(Ordering::Relaxed);
        metrics.pacing_rate = Some(self.cached_pacing_rate.load(Ordering::Relaxed));
        metrics
    }

    fn clone_box(&self) -> Box<dyn Controller> {
        Box::new(self.clone())
    }

    fn initial_window(&self) -> u64 {
        self.target_window()
    }

    fn into_any(self: Box<Self>) -> Box<dyn Any> {
        self
    }
}

impl Clone for BrutalController {
    fn clone(&self) -> Self {
        Self {
            bytes_per_second: Arc::clone(&self.bytes_per_second),
            mtu: self.mtu,
            started: self.started,
            rtt: self.rtt,
            ack_rate: self.ack_rate,
            slots: self.slots,
            cached_rate: AtomicU64::new(self.cached_rate.load(Ordering::Relaxed)),
            cached_window: AtomicU64::new(self.cached_window.load(Ordering::Relaxed)),
            cached_pacing_rate: AtomicU64::new(self.cached_pacing_rate.load(Ordering::Relaxed)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiates_server_and_client_limits() {
        let config = Hy2CongestionConfig::new(10_000_000);
        assert_eq!(config.negotiated_rate(5_000_000), 5_000_000);
        assert_eq!(config.negotiated_rate(20_000_000), 10_000_000);
        assert_eq!(config.negotiated_rate(0), 0);
    }

    #[test]
    fn loss_compensation_increases_window() {
        let now = Instant::now();
        let mut controller = BrutalController::new(Arc::new(AtomicU64::new(10_000_000)), 1200, now);
        let baseline = controller.window();
        controller.record(now + Duration::from_secs(1), 60_000, 60_000);
        assert_eq!(controller.ack_rate, MIN_ACK_RATE);
        assert!(controller.window() > baseline);
    }
}
