mod auth;
mod tcp;
mod udp;
mod varint;

pub use auth::{
    AuthRequest, AuthResponse, HEADER_CC_RX, REQUEST_HEADER_AUTH, RESPONSE_HEADER_UDP_ENABLED,
    STATUS_AUTH_OK,
};
pub use tcp::{TcpRequest, TcpResponse, TcpResponseStatus};
pub use udp::{UdpMessage, UdpReassembler};
pub use varint::{decode_varint, encode_varint};

pub const MAX_ADDRESS_LENGTH: usize = 2048;
pub const MAX_MESSAGE_LENGTH: usize = 2048;
pub const MAX_PADDING_LENGTH: usize = 4096;
pub const MAX_UDP_SIZE: usize = 4096;
pub const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
