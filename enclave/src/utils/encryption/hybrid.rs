use crate::utils::encryption::EncryptionError;
use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use k256::ecdh::diffie_hellman;
use k256::{PublicKey, SecretKey, ecdh::EphemeralSecret};
use sha2::{Digest, Sha256};

pub fn hybrid_encrypt(
    receiver_public_key_string: String,
    data: &[u8],
) -> Result<(String, String), EncryptionError> {
    let receiver_public_key = base64_to_public_key(&receiver_public_key_string)?;
    let ephemeral_secret_key = EphemeralSecret::random(&mut OsRng);
    let ephemeral_public_key = PublicKey::from(&ephemeral_secret_key);

    let shared_secret = ephemeral_secret_key.diffie_hellman(&receiver_public_key);

    let mut hasher = Sha256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    let symmetric_key = hasher.finalize();

    let cipher = Aes256Gcm::new(symmetric_key.as_slice().into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, data).map_err(|_| {
        EncryptionError::ErrorSigningData("Failed to sign data provide".to_string())
    })?;

    let mut encrypted_data = nonce.to_vec();
    encrypted_data.extend_from_slice(&ciphertext);

    Ok((
        public_key_to_base64(&ephemeral_public_key),
        BASE64.encode(encrypted_data),
    ))
}

pub fn hybrid_decrypt(
    receiver_secret_key_string: String,
    ephemeral_public_key_string: String,
    encrypted_data: String,
) -> Result<Vec<u8>, EncryptionError> {
    let receiver_secret_key = base64_to_secret_key(&receiver_secret_key_string)?;

    let encrypted_data_byte = BASE64.decode(encrypted_data).map_err(|_| {
        EncryptionError::InvalidSecretKey("Failed to create Secret Key from slice".to_string())
    })?;
    if encrypted_data_byte.len() <= 12 {
        return Err(EncryptionError::InvalidEncryptedData(
            "Encrypted data is too short".to_string(),
        ));
    }
    let nonce_bytes = &encrypted_data_byte[..12];
    let ciphertext = &encrypted_data_byte[12..];

    let nonce = Nonce::from_slice(nonce_bytes);

    let public_key = base64_to_public_key(&ephemeral_public_key_string)?;
    let shared_secret = diffie_hellman(
        receiver_secret_key.to_nonzero_scalar(),
        public_key.as_affine(),
    );

    let mut hasher = Sha256::new();
    hasher.update(shared_secret.raw_secret_bytes());
    let symmetric_key = hasher.finalize();

    let cipher = Aes256Gcm::new(symmetric_key.as_slice().into());

    let data = cipher.decrypt(nonce, ciphertext).map_err(|_| {
        EncryptionError::ErrorSigningData("Failed to sign data provide".to_string())
    })?;

    Ok(data)
}

pub fn hybrid_re_encrypt(
    old_secret_key_string: String,
    ephemeral_public_key_string: String,
    encrypted_data: String,
    new_public_key_string: String,
) -> Result<(String, String), EncryptionError> {
    let data = hybrid_decrypt(
        old_secret_key_string,
        ephemeral_public_key_string,
        encrypted_data,
    )?;
    hybrid_encrypt(new_public_key_string, &data)
}

fn secret_key_to_base64(secret_key: &SecretKey) -> String {
    let bytes = secret_key.to_bytes();
    BASE64.encode(bytes)
}

fn public_key_to_base64(public_key: &PublicKey) -> String {
    BASE64.encode(public_key.to_sec1_bytes())
}

fn base64_to_secret_key(base64_str: &str) -> Result<SecretKey, EncryptionError> {
    let decoded_bytes = BASE64.decode(base64_str).map_err(|_| {
        EncryptionError::InvalidSecretKey("Failed to create Secret Key from slice".to_string())
    })?;

    let secret_key = SecretKey::from_slice(&decoded_bytes).map_err(|_| {
        EncryptionError::InvalidSecretKey("The Secret Key provided is invalid".to_string())
    })?;
    Ok(secret_key)
}

fn base64_to_public_key(base64_str: &str) -> Result<PublicKey, EncryptionError> {
    let decoded_bytes = BASE64.decode(base64_str).map_err(|_| {
        EncryptionError::InvalidPublicKey("Failed to create Public Key from slice".to_string())
    })?;

    let public_key = PublicKey::from_sec1_bytes(&decoded_bytes).map_err(|_| {
        EncryptionError::InvalidPublicKey("The Public Key provided is invalid".to_string())
    })?;
    Ok(public_key)
}

#[cfg(test)]
mod test {
    use super::*;

    fn generate_receiver_keypair() -> (SecretKey, PublicKey) {
        let secret_key = SecretKey::random(&mut OsRng);
        let public_key = secret_key.public_key();
        (secret_key, public_key)
    }

    #[test]
    fn test_base64_to_keys() {
        let (secret_key, public_key) = generate_receiver_keypair();
        let secret_key_string = secret_key_to_base64(&secret_key);
        let public_key_string = public_key_to_base64(&public_key);

        let reconverted_secret_key = base64_to_secret_key(&secret_key_string).unwrap();
        let reconverted_public_key = base64_to_public_key(&public_key_string).unwrap();

        assert_eq!(secret_key, reconverted_secret_key);
        assert_eq!(public_key, reconverted_public_key);
    }

    #[test]
    fn test_hybrid_encrypt_and_hybrid_decrypt() {
        let (secret_key, public_key) = generate_receiver_keypair();
        let secret_key_string = secret_key_to_base64(&secret_key);
        let public_key_string = public_key_to_base64(&public_key);

        let data = "this is a secret";

        let (ephemeral_public_key, encrypted_data) =
            hybrid_encrypt(public_key_string, data.as_bytes()).unwrap();

        let decrypted_data =
            hybrid_decrypt(secret_key_string, ephemeral_public_key, encrypted_data).unwrap();

        assert_eq!(data.as_bytes(), decrypted_data)
    }

    #[test]
    fn test_hybrid_re_encrypt() {
        let (secret_key, public_key) = generate_receiver_keypair();
        let secret_key_string = secret_key_to_base64(&secret_key);
        let public_key_string = public_key_to_base64(&public_key);

        let data = "this is a secret";

        let (ephemeral_public_key, encrypted_data) =
            hybrid_encrypt(public_key_string, data.as_bytes()).unwrap();

        let (new_secret_key, new_public_key) = generate_receiver_keypair();
        let new_secret_key_string = secret_key_to_base64(&new_secret_key);
        let new_public_key_string = public_key_to_base64(&new_public_key);

        let (new_ephemeral_public_key, new_encrypted_data) = hybrid_re_encrypt(
            secret_key_string,
            ephemeral_public_key.clone(),
            encrypted_data.clone(),
            new_public_key_string,
        )
        .unwrap();

        let new_decrypted_data = hybrid_decrypt(
            new_secret_key_string,
            new_ephemeral_public_key.clone(),
            new_encrypted_data.clone(),
        )
        .unwrap();

        assert_ne!(new_encrypted_data, encrypted_data);
        assert_ne!(ephemeral_public_key, new_ephemeral_public_key);
        assert_eq!(data.as_bytes(), new_decrypted_data);
    }
}
