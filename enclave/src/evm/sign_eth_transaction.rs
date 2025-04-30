use alloy::consensus::transaction::RlpEcdsaEncodableTx;
use alloy::network::{TxSignerSync};
use alloy::primitives::ruint::ParseError;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::{local::PrivateKeySigner};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Failed to load private key: {0}")]
    PrivateKeyLoadError(String),
    #[error("Invalid private key format: {0}")]
    InvalidPrivateKey(#[from] ParseError),
    #[error("Failed to parse hex: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Signing operation failed: {0}")]
    SigningFailed(String),
    #[error("Invalid transaction")]
    InvalidTransaction(String),
    #[error("Invalid Address")]
    InvalidAddress(String),
    #[error("EIP-712 encoding failed: {0}")]
    Eip712Error(#[from] alloy::sol_types::Error),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Secp256k1 signing error: {0}")]
    Secp256k1Error(#[from] k256::ecdsa::Error),
}

pub async fn sign(
    transaction_request: TransactionRequest,
    wallet: &PrivateKeySigner,
) -> Result<String, SigningError> {
    let mut typed_transaction = transaction_request
        .build_typed_tx()
        .map_err(|_| SigningError::InvalidTransaction("Invalid transaction".to_string()))?;

    wallet
        .sign_transaction_sync(&mut typed_transaction)
        .map_err(|e| SigningError::SigningFailed(e.to_string()))?;

    let mut encoded = Vec::new();
    typed_transaction
        .rlp_encode(&mut encoded);

    let hex_tx = hex::encode(&encoded);

    Ok(format!("0x{}", hex_tx))
}
