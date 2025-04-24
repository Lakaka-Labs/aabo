use thiserror::Error;

pub mod hybrid;
pub mod kms;

#[derive(Error, Debug)]
pub enum EncryptionError {
    #[error("Secret Key provided is invalid")]
    InvalidSecretKey(String),
    #[error("Encrypted data is invalid")]
    InvalidEncryptedData(String),
    #[error("Public Key provided is invalid")]
    InvalidPublicKey(String),
    #[error("Failed to sign data provide")]
    ErrorSigningData(String),
    #[error("Failed to initialize SDK")]
    SdkInitError,
    #[error("An unknown SDK error occurred")]
    SdkGenericError,
    #[error("Invalid KMS configuration")]
    SdkKmsConfigError,
    #[error("Failed to create KMS client")]
    SdkKmsClientError,
    #[error("KMS decryption failed")]
    SdkKmsDecryptError,
    #[error("KMS encryption failed")]
    SdkKmsEncryptError,
}
