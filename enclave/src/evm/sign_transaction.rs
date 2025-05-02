use alloy::consensus::Signed;
use alloy::network::{TransactionBuilder, TxSignerSync};
use alloy::primitives::B256;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::Signature;
use alloy::signers::local::PrivateKeySigner;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum SigningError {
    #[error("Failed to parse hex: {0}")]
    HexError(#[from] hex::FromHexError),
    #[error("Signing operation failed: {0}")]
    SigningFailed(String),
    #[error("Invalid transaction")]
    InvalidTransaction(String),
    #[error("EIP-712 encoding failed: {0}")]
    Eip712Error(#[from] alloy::sol_types::Error),
    #[error("JSON serialization/deserialization error: {0}")]
    JsonError(#[from] serde_json::Error),
    #[error("Secp256k1 signing error: {0}")]
    Secp256k1Error(#[from] k256::ecdsa::Error),
}

pub fn sign_transaction(
    transaction_request: TransactionRequest,
    wallet: &PrivateKeySigner,
) -> Result<String, SigningError> {
    let mut typed_transaction = transaction_request
        .build_unsigned()
        .map_err(|_| SigningError::InvalidTransaction("Invalid transaction".to_string()))?;

    let signature: Signature = wallet
        .sign_transaction_sync(&mut typed_transaction)
        .map_err(|e| SigningError::SigningFailed(e.to_string()))?;
    let signed_tx = Signed::new_unchecked(typed_transaction, signature, B256::ZERO);

    let mut rlp_buf = Vec::<u8>::new();
    signed_tx.rlp_encode(&mut rlp_buf);

    let hex_tx = hex::encode(&rlp_buf);

    Ok(format!("0x02{}", hex_tx))
}

#[cfg(test)]
mod test {
    use crate::evm::sign_transaction::sign_transaction;
    use alloy::rpc::types::TransactionRequest;
    use alloy::signers::local::PrivateKeySigner;

    #[test]
    fn test_legacy_transfer() {
        let wallet: PrivateKeySigner = "CE75F1A875F2DB7FB064F5DBD302B0C77FFEAA18CC4C314167A5111A04F79AFA" // dummy private key
            .parse()
            .unwrap();

        let tx_json = r#"{
            "to": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "gas": "0x15f90",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x3b9aca00",
            "maxFeePerBlobGas": "0xa",
            "nonce": "1",
            "chainId": "1",
            "blobVersionedHashes": ["0x01cf3c34d3feed2066b1879d7f33c697554c94761940aa34f4f198709c4ef1d1"]
        }"#;

        let tx: TransactionRequest =
            serde_json::from_str(tx_json).expect("Failed to deserialize legacy tx");

        let signed_transaction = sign_transaction(tx, &wallet).unwrap();
        // assert_eq!(
        //     "0x02f874010485012a05f2008504a817c800825208940395001fab2f2373d8741d341ca614c472502c9d880de0b6b3a764000080c001a02c95f6c35b96a4600cb7d39fa793eef41ed5607772b3d828c3a0a2101b1e7584a0076ce04d76aa7d064c9bf408987aed6b6cdbe9d781889fcd6c4adf27ac0c7493",
        //     signed_transaction
        // )
    }
    
    #[test]
    fn test_eip1559_transfer() {
        let wallet: PrivateKeySigner = "CE75F1A875F2DB7FB064F5DBD302B0C77FFEAA18CC4C314167A5111A04F79AFA" // dummy private key
            .parse()
            .unwrap();

        let tx_json = r#"{
          "to": "0x0395001fAB2F2373D8741d341Ca614c472502C9d",
          "gas": "0x5208",
          "value": "0x0de0b6b3a7640000",
          "maxPriorityFeePerGas":"0x012a05f200",
          "maxFeePerGas":"0x04a817c800",
          "nonce": "4",
          "chainId": "1"
        }"#;

        let tx: TransactionRequest =
            serde_json::from_str(tx_json).expect("Failed to deserialize legacy tx");

        let signed_transaction = sign_transaction(tx, &wallet).unwrap();
        assert_eq!(
            "0x02f874010485012a05f2008504a817c800825208940395001fab2f2373d8741d341ca614c472502c9d880de0b6b3a764000080c001a02c95f6c35b96a4600cb7d39fa793eef41ed5607772b3d828c3a0a2101b1e7584a0076ce04d76aa7d064c9bf408987aed6b6cdbe9d781889fcd6c4adf27ac0c7493",
            signed_transaction
        )
    }
    #[test]
    fn test_eip1559_contract_call() {
        let wallet: PrivateKeySigner = "CE75F1A875F2DB7FB064F5DBD302B0C77FFEAA18CC4C314167A5111A04F79AFA" // dummy private key
            .parse()
            .unwrap();

        let tx_json = r#"{
          "to": "0x6B175474E89094C44Da98b954EedeAC495271d0F",
          "gas": "0x5208",
          "maxPriorityFeePerGas":"0x012a05f200",
          "maxFeePerGas":"0x04a817c800",
          "input": "0xa9059cbb000000000000000000000000def1234567890abcde1234567890abcdef1234560000000000000000000000000000000000000000000000000000000000000064",
          "nonce": "5",
          "chainId": "1"
        }"#;

        let tx: TransactionRequest =
            serde_json::from_str(tx_json).expect("Failed to deserialize legacy tx");
        

        let signed_transaction = sign_transaction(tx, &wallet).unwrap();
        println!("{signed_transaction}");
        // assert_eq!(
        //     "0x02f86c058504a817c800825208940395001fab2f2373d8741d341ca614c472502c9d880de0b6b3a76400008080a0c62fd8ed166b1935fd9925527a9518f906352a1cd06571672eef26cf270508eaa05e8ebeeb5dc2ba7b3930a50f33e879860c090ea3f52f858b3a17a2299861ab46",
        //     signed_transaction
        // )
    }
}
