use std::{
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use quinn::{
    AsyncUdpSocket, UdpPoller,
    udp::{RecvMeta, Transmit},
};

use crate::salamander::{SALT_LENGTH, apply_keystream};

pub(crate) struct SalamanderSocket {
    inner: Arc<dyn AsyncUdpSocket>,
    password: Arc<[u8]>,
}

impl SalamanderSocket {
    pub(crate) fn new(inner: Arc<dyn AsyncUdpSocket>, password: impl Into<Vec<u8>>) -> Self {
        Self {
            inner,
            password: Arc::from(password.into()),
        }
    }

    fn encrypt_transmit(&self, transmit: &Transmit<'_>) -> io::Result<(Vec<u8>, Option<usize>)> {
        let source_segment_size = transmit.segment_size.unwrap_or(transmit.contents.len());
        if source_segment_size == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty Salamander UDP transmit",
            ));
        }
        let segment_count = transmit.contents.len().div_ceil(source_segment_size);
        let mut salts = vec![0_u8; segment_count * SALT_LENGTH];
        getrandom::fill(&mut salts).map_err(io::Error::other)?;
        let mut encrypted =
            Vec::with_capacity(transmit.contents.len() + segment_count * SALT_LENGTH);
        for (index, segment) in transmit.contents.chunks(source_segment_size).enumerate() {
            let salt: [u8; SALT_LENGTH] = salts[index * SALT_LENGTH..(index + 1) * SALT_LENGTH]
                .try_into()
                .expect("exact Salamander salt length");
            encrypted.extend_from_slice(&salt);
            let payload_start = encrypted.len();
            encrypted.extend_from_slice(segment);
            apply_keystream(&self.password, &salt, &mut encrypted[payload_start..]);
        }
        Ok((
            encrypted,
            transmit.segment_size.map(|size| size + SALT_LENGTH),
        ))
    }

    fn decrypt_receive_batch(
        &self,
        count: usize,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> usize {
        let mut target = 0;
        for index in 0..count {
            let source_meta = meta[index];
            let source_stride = if source_meta.stride == 0 {
                source_meta.len
            } else {
                source_meta.stride
            };
            if source_stride <= SALT_LENGTH || source_meta.len > bufs[index].len() {
                continue;
            }
            if (0..source_meta.len)
                .step_by(source_stride)
                .any(|start| (start + source_stride).min(source_meta.len) - start <= SALT_LENGTH)
            {
                continue;
            }
            let mut plain_length = 0;
            for start in (0..source_meta.len).step_by(source_stride) {
                let end = (start + source_stride).min(source_meta.len);
                let salt: [u8; SALT_LENGTH] = bufs[index][start..start + SALT_LENGTH]
                    .try_into()
                    .expect("validated Salamander segment salt");
                let payload_start = start + SALT_LENGTH;
                apply_keystream(&self.password, &salt, &mut bufs[index][payload_start..end]);
                bufs[index].copy_within(payload_start..end, plain_length);
                plain_length += end - payload_start;
            }
            let mut plain_meta = source_meta;
            plain_meta.len = plain_length;
            plain_meta.stride = source_stride - SALT_LENGTH;
            if target != index {
                let (target_buffers, source_buffers) = bufs.split_at_mut(index);
                target_buffers[target][..plain_length]
                    .copy_from_slice(&source_buffers[0][..plain_length]);
            }
            meta[target] = plain_meta;
            target += 1;
        }
        target
    }
}

impl fmt::Debug for SalamanderSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SalamanderSocket")
            .field("inner", &self.inner)
            .field("password", &"[redacted]")
            .finish()
    }
}

impl AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Arc::clone(&self.inner).create_io_poller()
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let (contents, segment_size) = self.encrypt_transmit(transmit)?;
        self.inner.try_send(&Transmit {
            destination: transmit.destination,
            ecn: transmit.ecn,
            contents: &contents,
            segment_size,
            src_ip: transmit.src_ip,
        })
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        loop {
            let count = match self.inner.poll_recv(cx, bufs, meta) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Ready(Ok(count)) => count,
            };
            let decoded = self.decrypt_receive_batch(count, bufs, meta);
            if decoded > 0 {
                return Poll::Ready(Ok(decoded));
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.inner.local_addr()
    }

    fn max_transmit_segments(&self) -> usize {
        self.inner.max_transmit_segments()
    }

    fn max_receive_segments(&self) -> usize {
        self.inner.max_receive_segments()
    }

    fn may_fragment(&self) -> bool {
        // Disable QUIC path-MTU discovery because Salamander adds 8 bytes after
        // QUIC has sized each UDP datagram.
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decrypts_multiple_gro_segments_and_updates_metadata() {
        let first = crate::salamander::encrypt(b"password", [1; SALT_LENGTH], b"first");
        let second = crate::salamander::encrypt(b"password", [2; SALT_LENGTH], b"other");
        let stride = first.len();
        let mut packet = [first, second].concat();
        let packet_length = packet.len();
        let mut buffers = [IoSliceMut::new(&mut packet)];
        let mut metadata = [RecvMeta {
            len: packet_length,
            stride,
            ..RecvMeta::default()
        }];
        let socket = SalamanderSocket {
            inner: Arc::new(PanicSocket),
            password: Arc::from(&b"password"[..]),
        };

        assert_eq!(
            socket.decrypt_receive_batch(1, &mut buffers, &mut metadata),
            1
        );
        assert_eq!(&buffers[0][..10], b"firstother");
        assert_eq!(metadata[0].len, 10);
        assert_eq!(metadata[0].stride, 5);
    }

    #[derive(Debug)]
    struct PanicSocket;

    impl AsyncUdpSocket for PanicSocket {
        fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
            panic!("not used")
        }

        fn try_send(&self, _: &Transmit<'_>) -> io::Result<()> {
            panic!("not used")
        }

        fn poll_recv(
            &self,
            _: &mut Context<'_>,
            _: &mut [IoSliceMut<'_>],
            _: &mut [RecvMeta],
        ) -> Poll<io::Result<usize>> {
            panic!("not used")
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            panic!("not used")
        }
    }
}
