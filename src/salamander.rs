use blake2::{
    Blake2bVar,
    digest::{Update, VariableOutput},
};
use thiserror::Error;

pub const SALT_LENGTH: usize = 8;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum SalamanderError {
    #[error("Salamander packet is shorter than its salt")]
    Truncated,
}

pub fn encrypt(password: &[u8], salt: [u8; SALT_LENGTH], payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(SALT_LENGTH + payload.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(payload);
    apply_keystream(password, &salt, &mut output[SALT_LENGTH..]);
    output
}

pub fn decrypt(password: &[u8], packet: &[u8]) -> Result<Vec<u8>, SalamanderError> {
    if packet.len() <= SALT_LENGTH {
        return Err(SalamanderError::Truncated);
    }
    let salt: [u8; SALT_LENGTH] = packet[..SALT_LENGTH].try_into().expect("exact salt length");
    let mut output = packet[SALT_LENGTH..].to_vec();
    apply_keystream(password, &salt, &mut output);
    Ok(output)
}

pub(crate) fn apply_keystream(password: &[u8], salt: &[u8; SALT_LENGTH], payload: &mut [u8]) {
    let key = derive_key(password, salt);
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= key[index % key.len()];
    }
}

fn derive_key(password: &[u8], salt: &[u8; SALT_LENGTH]) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid BLAKE2b output length");
    hasher.update(password);
    hasher.update(salt);
    let mut key = [0_u8; 32];
    hasher
        .finalize_variable(&mut key)
        .expect("output length matches");
    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypts_and_decrypts_like_salamander() {
        let plain = b"HY2 datagram";
        let encrypted = encrypt(b"password", [1, 2, 3, 4, 5, 6, 7, 8], plain);
        assert_eq!(encrypted.len(), plain.len() + SALT_LENGTH);
        assert_ne!(&encrypted[SALT_LENGTH..], plain);
        assert_eq!(decrypt(b"password", &encrypted).unwrap(), plain);
    }
}
