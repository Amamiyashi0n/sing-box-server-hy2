use thiserror::Error;

use super::{
    FRAME_TYPE_TCP_REQUEST, MAX_ADDRESS_LENGTH, MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH,
    decode_varint, encode_varint,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TcpCodecError {
    #[error("invalid HY2 frame type: {0:#x}")]
    InvalidFrameType(u64),
    #[error("invalid {field} length: {length}")]
    InvalidLength { field: &'static str, length: usize },
    #[error("truncated HY2 TCP frame")]
    Truncated,
    #[error(transparent)]
    VarInt(#[from] super::varint::VarIntError),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpRequest {
    pub destination: String,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TcpResponseStatus {
    Ok = 0,
    Error = 1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpResponse {
    pub status: TcpResponseStatus,
    pub message: String,
    pub payload: Vec<u8>,
}

impl TcpRequest {
    pub fn decode(input: &mut &[u8]) -> Result<Self, TcpCodecError> {
        let frame_type = decode_varint(input)?;
        if frame_type != FRAME_TYPE_TCP_REQUEST {
            return Err(TcpCodecError::InvalidFrameType(frame_type));
        }
        let address = read_limited(input, MAX_ADDRESS_LENGTH, "address")?;
        if address.is_empty() {
            return Err(TcpCodecError::InvalidLength {
                field: "address",
                length: 0,
            });
        }
        let padding = read_limited(input, MAX_PADDING_LENGTH, "padding")?;
        let _ = padding;
        Ok(Self {
            destination: String::from_utf8_lossy(&address).into_owned(),
            payload: input.to_vec(),
        })
    }

    pub fn encode(
        destination: &str,
        padding: &[u8],
        payload: &[u8],
    ) -> Result<Vec<u8>, TcpCodecError> {
        validate_len(destination.len(), MAX_ADDRESS_LENGTH, "address")?;
        if destination.is_empty() {
            return Err(TcpCodecError::InvalidLength {
                field: "address",
                length: 0,
            });
        }
        validate_len(padding.len(), MAX_PADDING_LENGTH, "padding")?;
        let mut output = Vec::with_capacity(destination.len() + padding.len() + payload.len() + 24);
        encode_varint(FRAME_TYPE_TCP_REQUEST, &mut output)?;
        write_bytes(destination.as_bytes(), &mut output)?;
        write_bytes(padding, &mut output)?;
        output.extend_from_slice(payload);
        Ok(output)
    }
}

impl TcpResponse {
    pub fn encode(&self, padding: &[u8]) -> Result<Vec<u8>, TcpCodecError> {
        validate_len(self.message.len(), MAX_MESSAGE_LENGTH, "message")?;
        validate_len(padding.len(), MAX_PADDING_LENGTH, "padding")?;
        let mut output =
            Vec::with_capacity(self.message.len() + padding.len() + self.payload.len() + 24);
        output.push(self.status as u8);
        write_bytes(self.message.as_bytes(), &mut output)?;
        write_bytes(padding, &mut output)?;
        output.extend_from_slice(&self.payload);
        Ok(output)
    }
}

fn write_bytes(bytes: &[u8], output: &mut Vec<u8>) -> Result<(), TcpCodecError> {
    encode_varint(bytes.len() as u64, output)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn read_limited(
    input: &mut &[u8],
    maximum: usize,
    field: &'static str,
) -> Result<Vec<u8>, TcpCodecError> {
    let length = decode_varint(input)? as usize;
    validate_len(length, maximum, field)?;
    if input.len() < length {
        return Err(TcpCodecError::Truncated);
    }
    let value = input[..length].to_vec();
    *input = &input[length..];
    Ok(value)
}

fn validate_len(length: usize, maximum: usize, field: &'static str) -> Result<(), TcpCodecError> {
    if length > maximum {
        return Err(TcpCodecError::InvalidLength { field, length });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_tcp_request_and_preserves_early_payload() {
        let encoded = TcpRequest::encode("example.com:443", b"padding", b"hello").unwrap();
        let request = TcpRequest::decode(&mut encoded.as_slice()).unwrap();
        assert_eq!(request.destination, "example.com:443");
        assert_eq!(request.payload, b"hello");
    }

    #[test]
    fn refuses_oversized_address() {
        let destination = "a".repeat(MAX_ADDRESS_LENGTH + 1);
        assert!(matches!(
            TcpRequest::encode(&destination, b"", b""),
            Err(TcpCodecError::InvalidLength {
                field: "address",
                ..
            })
        ));
    }

    #[test]
    fn encodes_success_response() {
        let response = TcpResponse {
            status: TcpResponseStatus::Ok,
            message: String::new(),
            payload: b"data".to_vec(),
        };
        assert_eq!(
            response.encode(b"").unwrap(),
            vec![0, 0, 0, b'd', b'a', b't', b'a']
        );
    }
}
