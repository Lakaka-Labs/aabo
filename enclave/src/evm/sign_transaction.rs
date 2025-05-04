use alloy::consensus::{Signed, Transaction};
use alloy::network::{TransactionBuilder, TxSignerSync};
use alloy::primitives::B256;
use alloy::rpc::types::TransactionRequest;
use alloy::signers::Signature;
use alloy::signers::local::PrivateKeySigner;
use crate::evm::SigningError;

fn u64_to_be(value: u64) -> [u8; 32] {
    let bytes = value.to_be_bytes();
    let mut array = [0u8; 32];
    array[..8].copy_from_slice(&bytes);
    array
}
pub fn sign_transaction(
    transaction_request: TransactionRequest,
    wallet: &PrivateKeySigner,
) -> Result<String, SigningError> {
    let mut typed_transaction = transaction_request
        .build_unsigned()
        .map_err(|e| SigningError::InvalidTransaction(e.to_string()))?;

    let signature: Signature = wallet
        .sign_transaction_sync(&mut typed_transaction)
        .map_err(|e| SigningError::SigningFailed(e.to_string()))?;

    let chain_id = typed_transaction.chain_id().unwrap_or_else(|| 0);
    let signed_tx = Signed::new_unchecked(
        typed_transaction,
        signature,
        B256::new(u64_to_be(chain_id)),
    );

    let mut rlp_buf = Vec::<u8>::new();
    signed_tx.rlp_encode(&mut rlp_buf);

    let hex_tx = hex::encode(&rlp_buf);

    Ok(format!("0x02{}", hex_tx))
}

#[cfg(test)]
mod test {
    use crate::evm::sign_transaction::sign_transaction;
    use alloy::consensus::transaction::RlpEcdsaDecodableTx;
    use alloy::consensus::{
        Signed, TxEip1559, TxEip2930, TxEip4844Variant, TxEnvelope, TxLegacy, TxType,
        TypedTransaction,
    };
    use alloy::eips::Decodable2718;
    use alloy::rlp::Decodable;
    use alloy::rpc::types::TransactionRequest;
    use alloy::signers::local::PrivateKeySigner;

    fn decode_signed_tx<T: RlpEcdsaDecodableTx>(signed_transaction: String) -> Signed<T> {
        let stripped_hex = signed_transaction
            .strip_prefix("0x02")
            .unwrap_or(&signed_transaction);
        let tx_bytes = hex::decode(stripped_hex).unwrap();

        let decoded_envelope: Signed<T> = Signed::rlp_decode(&mut tx_bytes.as_slice()).unwrap();
        decoded_envelope
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
        );
        let _decoded_tx = decode_signed_tx::<TxEip1559>(signed_transaction);
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
        assert_eq!(
            "0x02f8b1010585012a05f2008504a817c800825208946b175474e89094c44da98b954eedeac495271d0f80b844a9059cbb000000000000000000000000def1234567890abcde1234567890abcdef1234560000000000000000000000000000000000000000000000000000000000000064c001a0d3f593d3636e79e371839479f485e4d8729712b6f3f7c92a21e1e3a3f53b8712a01e38e2d6c0034a2e892720777cfd829afbec1891eb0cf2a7a571b2256f0ab3cb",
            signed_transaction
        );
        let _decoded_tx = decode_signed_tx::<TxEip1559>(signed_transaction);
    }

    #[test]
    fn test_eip2930() {
        let wallet: PrivateKeySigner = "CE75F1A875F2DB7FB064F5DBD302B0C77FFEAA18CC4C314167A5111A04F79AFA" // dummy private key
            .parse()
            .unwrap();

        let tx_json = r#"{
          "to": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
          "gas": "0xc350",
          "gasPrice": "0x4a817c800",
          "value": "0x0",
          "input": "0xaabbccdd",
          "nonce": "0x2",
          "chainId": "0x1",
          "type": "0x1",
          "accessList": [
            {
              "address": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
              "storageKeys": [
                "0x0000000000000000000000000000000000000000000000000000000000000000"
              ]
            }
          ]
        }"#;

        let tx: TransactionRequest =
            serde_json::from_str(tx_json).expect("Failed to deserialize legacy tx");

        let signed_transaction = sign_transaction(tx, &wallet).unwrap();
        assert_eq!(
            "0x02f8a301028504a817c80082c35094d8da6bf26964af9d7eed9e03e53415d37aa960458084aabbccddf838f7945fbdb2315678afecb367f032d93f642f64180aa3e1a0000000000000000000000000000000000000000000000000000000000000000080a02bf80e5d10980c7d4f4257acef710cde6eb9f913ed03c638b53afac80c2f92fea078b43d4f3549ab84c4c8f97c1afd2c3d92844d02afec0907c1dc5096fcefaceb",
            signed_transaction
        );

        let _decoded_tx = decode_signed_tx::<TxEip2930>(signed_transaction);
    }
}
