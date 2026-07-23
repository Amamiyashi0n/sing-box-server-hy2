use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum VarIntError {
    #[error("unexpected end of QUIC varint")]
    Truncated,
    #[error("QUIC varint exceeds 62 bits")]
    TooLarge,
}

pub fn encode_varint(value: u64, output: &mut Vec<u8>) -> Result<(), VarIntError> {
    let (width, prefix) = match value {
        0..=63 => (1, 0_u8),
        64..=16_383 => (2, 0x40),
        16_384..=1_073_741_823 => (4, 0x80),
        1_073_741_824..=4_611_686_018_427_387_903 => (8, 0xc0),
        _ => return Err(VarIntError::TooLarge),
    };
    let mut bytes = value.to_be_bytes();
    let start = bytes.len() - width;
    bytes[start] |= prefix;
    output.extend_from_slice(&bytes[start..]);
    Ok(())
}

pub fn decode_varint(input: &mut &[u8]) -> Result<u64, VarIntError> {
    let first = *input.first().ok_or(VarIntError::Truncated)?;
    let width = 1_usize << (first >> 6);
    if input.len() < width {
        return Err(VarIntError::Truncated);
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &input[1..width] {
        value = (value << 8) | u64::from(*byte);
    }
    *input = &input[width..];
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_each_varint_width() {
        for value in [
            0,
            63,
            64,
            16_383,
            16_384,
            1_073_741_823,
            1_073_741_824,
            4_611_686_018_427_387_903,
        ] {
            let mut encoded = Vec::new();
            encode_varint(value, &mut encoded).unwrap();
            assert_eq!(decode_varint(&mut encoded.as_slice()).unwrap(), value);
        }
    }
}
