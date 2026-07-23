use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use thiserror::Error;

use super::{MAX_ADDRESS_LENGTH, MAX_UDP_SIZE, decode_varint, encode_varint};

const REASSEMBLY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INCOMPLETE_PACKETS: usize = 1024;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum UdpCodecError {
    #[error("UDP datagram is truncated")]
    Truncated,
    #[error("invalid HY2 UDP destination length: {0}")]
    InvalidDestination(usize),
    #[error("HY2 UDP payload exceeds {MAX_UDP_SIZE} bytes")]
    PayloadTooLarge,
    #[error("invalid HY2 UDP fragment metadata")]
    InvalidFragment,
    #[error("HY2 UDP datagram limit is too small")]
    DatagramLimitTooSmall,
    #[error(transparent)]
    VarInt(#[from] super::varint::VarIntError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage {
    pub session_id: u32,
    pub packet_id: u16,
    pub fragment_id: u8,
    pub fragment_count: u8,
    pub destination: String,
    pub payload: Vec<u8>,
}

impl UdpMessage {
    pub fn decode(input: &[u8]) -> Result<Self, UdpCodecError> {
        if input.len() < 9 {
            return Err(UdpCodecError::Truncated);
        }
        let session_id = u32::from_be_bytes(input[0..4].try_into().unwrap());
        let packet_id = u16::from_be_bytes(input[4..6].try_into().unwrap());
        let fragment_id = input[6];
        let fragment_count = input[7];
        let mut tail = &input[8..];
        let destination_length = decode_varint(&mut tail)? as usize;
        if destination_length == 0 || destination_length > MAX_ADDRESS_LENGTH {
            return Err(UdpCodecError::InvalidDestination(destination_length));
        }
        if tail.len() < destination_length {
            return Err(UdpCodecError::Truncated);
        }
        let destination = String::from_utf8_lossy(&tail[..destination_length]).into_owned();
        let payload = tail[destination_length..].to_vec();
        if payload.len() > MAX_UDP_SIZE {
            return Err(UdpCodecError::PayloadTooLarge);
        }
        Ok(Self {
            session_id,
            packet_id,
            fragment_id,
            fragment_count,
            destination,
            payload,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, UdpCodecError> {
        encode_fragment(
            self.session_id,
            self.packet_id,
            self.fragment_id,
            self.fragment_count,
            &self.destination,
            &self.payload,
        )
    }

    pub fn encode_fragments(
        session_id: u32,
        packet_id: u16,
        destination: &str,
        payload: &[u8],
        maximum_datagram_size: usize,
    ) -> Result<Vec<Vec<u8>>, UdpCodecError> {
        validate_message(destination, payload)?;
        let header_size = 8 + varint_size(destination.len() as u64) + destination.len();
        let payload_per_fragment = maximum_datagram_size
            .checked_sub(header_size)
            .filter(|size| *size > 0)
            .ok_or(UdpCodecError::DatagramLimitTooSmall)?;
        let fragment_count = payload.len().div_ceil(payload_per_fragment).max(1);
        if fragment_count > u8::MAX as usize {
            return Err(UdpCodecError::InvalidFragment);
        }
        if payload.is_empty() {
            return Ok(vec![encode_fragment(
                session_id,
                packet_id,
                0,
                1,
                destination,
                payload,
            )?]);
        }
        payload
            .chunks(payload_per_fragment)
            .enumerate()
            .map(|(fragment_id, fragment)| {
                encode_fragment(
                    session_id,
                    packet_id,
                    fragment_id as u8,
                    fragment_count as u8,
                    destination,
                    fragment,
                )
            })
            .collect()
    }

    pub fn fragment(&self, maximum_datagram_size: usize) -> Result<Vec<Self>, UdpCodecError> {
        let header_size = 8 + varint_size(self.destination.len() as u64) + self.destination.len();
        let payload_per_fragment = maximum_datagram_size
            .checked_sub(header_size)
            .filter(|size| *size > 0)
            .ok_or(UdpCodecError::DatagramLimitTooSmall)?;
        if self.payload.len() <= payload_per_fragment {
            return Ok(vec![self.clone()]);
        }
        let fragment_count = self.payload.len().div_ceil(payload_per_fragment);
        if fragment_count > u8::MAX as usize {
            return Err(UdpCodecError::InvalidFragment);
        }
        Ok(self
            .payload
            .chunks(payload_per_fragment)
            .enumerate()
            .map(|(fragment_id, payload)| Self {
                session_id: self.session_id,
                packet_id: self.packet_id,
                fragment_id: fragment_id as u8,
                fragment_count: fragment_count as u8,
                destination: self.destination.clone(),
                payload: payload.to_vec(),
            })
            .collect())
    }
}

fn validate_message(destination: &str, payload: &[u8]) -> Result<(), UdpCodecError> {
    if destination.is_empty() || destination.len() > MAX_ADDRESS_LENGTH {
        return Err(UdpCodecError::InvalidDestination(destination.len()));
    }
    if payload.len() > MAX_UDP_SIZE {
        return Err(UdpCodecError::PayloadTooLarge);
    }
    Ok(())
}

fn encode_fragment(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    destination: &str,
    payload: &[u8],
) -> Result<Vec<u8>, UdpCodecError> {
    validate_message(destination, payload)?;
    let mut output = Vec::with_capacity(16 + destination.len() + payload.len());
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_id);
    output.push(fragment_count);
    encode_varint(destination.len() as u64, &mut output)?;
    output.extend_from_slice(destination.as_bytes());
    output.extend_from_slice(payload);
    Ok(output)
}

#[derive(Default)]
pub struct UdpReassembler {
    packets: HashMap<(u32, u16), PartialPacket>,
}

struct PartialPacket {
    updated_at: Instant,
    destination: String,
    fragments: Vec<Option<Vec<u8>>>,
}

impl UdpReassembler {
    pub fn push(&mut self, message: UdpMessage) -> Result<Option<UdpMessage>, UdpCodecError> {
        self.push_at(message, Instant::now())
    }

    fn push_at(
        &mut self,
        message: UdpMessage,
        now: Instant,
    ) -> Result<Option<UdpMessage>, UdpCodecError> {
        self.packets
            .retain(|_, partial| now.duration_since(partial.updated_at) < REASSEMBLY_TIMEOUT);
        if message.fragment_count <= 1 {
            return Ok(Some(message));
        }
        if message.fragment_id >= message.fragment_count {
            return Err(UdpCodecError::InvalidFragment);
        }
        let key = (message.session_id, message.packet_id);
        let oldest = (!self.packets.contains_key(&key)
            && self.packets.len() >= MAX_INCOMPLETE_PACKETS)
            .then(|| {
                self.packets
                    .iter()
                    .min_by_key(|(_, partial)| partial.updated_at)
                    .map(|(key, _)| *key)
            })
            .flatten();
        if let Some(oldest) = oldest {
            self.packets.remove(&oldest);
        }
        let partial = self.packets.entry(key).or_insert_with(|| PartialPacket {
            updated_at: now,
            destination: message.destination.clone(),
            fragments: vec![None; message.fragment_count as usize],
        });
        if partial.destination != message.destination
            || partial.fragments.len() != message.fragment_count as usize
        {
            self.packets.remove(&key);
            return Err(UdpCodecError::InvalidFragment);
        }
        partial.updated_at = now;
        partial.fragments[message.fragment_id as usize] = Some(message.payload);
        if partial.fragments.iter().any(Option::is_none) {
            return Ok(None);
        }
        let partial = self
            .packets
            .remove(&key)
            .expect("packet remains while assembling");
        let payload_size = partial
            .fragments
            .iter()
            .flatten()
            .try_fold(0_usize, |total, fragment| total.checked_add(fragment.len()))
            .filter(|size| *size <= MAX_UDP_SIZE)
            .ok_or(UdpCodecError::PayloadTooLarge)?;
        let mut payload = Vec::with_capacity(payload_size);
        for fragment in partial.fragments.into_iter().flatten() {
            payload.extend_from_slice(&fragment);
        }
        Ok(Some(UdpMessage {
            session_id: key.0,
            packet_id: key.1,
            fragment_id: 0,
            fragment_count: 1,
            destination: partial.destination,
            payload,
        }))
    }
}

fn varint_size(value: u64) -> usize {
    match value {
        0..=63 => 1,
        64..=16_383 => 2,
        16_384..=1_073_741_823 => 4,
        _ => 8,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_udp_datagram() {
        let message = UdpMessage {
            session_id: 7,
            packet_id: 42,
            fragment_id: 0,
            fragment_count: 1,
            destination: "1.1.1.1:53".into(),
            payload: vec![1, 2, 3],
        };
        assert_eq!(
            UdpMessage::decode(&message.encode().unwrap()).unwrap(),
            message
        );
    }

    #[test]
    fn reassembles_fragments_in_any_order() {
        let message = UdpMessage {
            session_id: 1,
            packet_id: 2,
            fragment_id: 0,
            fragment_count: 1,
            destination: "127.0.0.1:53".into(),
            payload: vec![7; 100],
        };
        let mut fragments = message.fragment(32).unwrap();
        fragments.reverse();
        let mut reassembler = UdpReassembler::default();
        for fragment in fragments.iter().take(fragments.len() - 1) {
            assert!(reassembler.push(fragment.clone()).unwrap().is_none());
        }
        assert_eq!(
            reassembler
                .push(fragments.last().unwrap().clone())
                .unwrap()
                .unwrap()
                .payload,
            message.payload
        );
    }

    #[test]
    fn expires_incomplete_packets() {
        let first = UdpMessage {
            session_id: 1,
            packet_id: 1,
            fragment_id: 0,
            fragment_count: 2,
            destination: "127.0.0.1:53".into(),
            payload: vec![1],
        };
        let later = UdpMessage {
            packet_id: 2,
            ..first.clone()
        };
        let now = Instant::now();
        let mut reassembler = UdpReassembler::default();
        assert!(reassembler.push_at(first, now).unwrap().is_none());
        assert!(
            reassembler
                .push_at(later, now + REASSEMBLY_TIMEOUT)
                .unwrap()
                .is_none()
        );
        assert_eq!(reassembler.packets.len(), 1);
    }

    #[test]
    fn directly_encodes_fragments_without_changing_payload() {
        let payload = vec![9; 100];
        let fragments = UdpMessage::encode_fragments(3, 4, "127.0.0.1:53", &payload, 32)
            .unwrap()
            .into_iter()
            .map(|fragment| UdpMessage::decode(&fragment).unwrap())
            .collect::<Vec<_>>();
        assert!(fragments.len() > 1);
        assert_eq!(fragments[0].fragment_count as usize, fragments.len());
        assert_eq!(
            fragments
                .iter()
                .flat_map(|fragment| fragment.payload.iter().copied())
                .collect::<Vec<_>>(),
            payload
        );
    }

    #[test]
    fn directly_encodes_empty_payload_as_one_fragment() {
        let fragments = UdpMessage::encode_fragments(3, 4, "127.0.0.1:53", &[], 32).unwrap();
        assert_eq!(fragments.len(), 1);
        let decoded = UdpMessage::decode(&fragments[0]).unwrap();
        assert_eq!(decoded.fragment_count, 1);
        assert!(decoded.payload.is_empty());
    }
}
