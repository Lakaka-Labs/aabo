use crate::solana::SigningError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use solana_sdk::signature::Keypair;
use solana_sdk::transaction::Transaction;

pub fn sign_transaction(serialized_tx: &str, keypair: Keypair) -> Result<String, SigningError> {
    let tx_bytes = BASE64
        .decode(serialized_tx)
        .map_err(|e| SigningError::EncodingError(e.to_string()))?;
    let mut tx: Transaction = bincode::deserialize(&tx_bytes)
        .map_err(|e| SigningError::InvalidTransaction(e.to_string()))?;

    tx.sign(&[&keypair], tx.message.recent_blockhash);

    let signed_tx_bytes =
        bincode::serialize(&tx).map_err(|e| SigningError::SigningFailed(e.to_string()))?;

    let signed_tx_base64 = BASE64.encode(&signed_tx_bytes);

    Ok(signed_tx_base64)
}

#[cfg(test)]
mod test {}
