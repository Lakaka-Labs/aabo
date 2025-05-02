#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use alloy::primitives::{Address, B256, Bytes, TxKind, U256};
    use alloy::rpc::types::TransactionRequest;
    use serde_json;

    fn addr(s: &str) -> Address {
        Address::from_str(s).expect("Invalid address string in test")
    }

    fn u256(s: &str) -> U256 {
        U256::from_str(s).expect("Invalid U256 string in test")
    }

    fn b256(s: &str) -> B256 {
        B256::from_str(s).expect("Invalid B256 string in test")
    }

    fn bytes(s: &str) -> Bytes {
        Bytes::from_str(s).expect("Invalid Bytes string in test")
    }

    #[test]
    fn deserialize_legacy_transaction() {
        let json = r#"{
          "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
          "to": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
          "gas": "0x5208",
          "gasPrice": "0x4a817c800",
          "value": "0x2386F26FC10000",
          "input": "0x",
          "nonce": "0x1",
          "chainId": "0x1"
        }"#;

        let request: TransactionRequest =
            serde_json::from_str(json).expect("Failed to deserialize legacy tx");

        assert_eq!(
            request.from,
            Some(addr("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
        );
        assert_eq!(
            request.to,
            Some(TxKind::Call(addr(
                "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
            )))
        );
        assert_eq!(request.gas, Some(0x5208));
        assert_eq!(request.gas_price, Some(0x4a817c800));
        assert_eq!(request.value, Some(u256("0x2386F26FC10000")));
        assert_eq!(request.input.input, Some(bytes("0x")));
        assert_eq!(request.nonce, Some(0x1));
        assert_eq!(request.chain_id, Some(1));
        assert_eq!(request.transaction_type, None);
        assert!(request.max_fee_per_gas.is_none());
        assert!(request.max_priority_fee_per_gas.is_none());
        assert!(request.access_list.is_none());
    }

    #[test]
    fn deserialize_eip2930_transaction() {
        let json = r#"{
          "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
          "to": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
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

        let request: TransactionRequest =
            serde_json::from_str(json).expect("Failed to deserialize EIP-2930 tx");

        assert_eq!(
            request.from,
            Some(addr("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
        );
        assert_eq!(
            request.to,
            Some(TxKind::Call(addr(
                "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
            )))
        );
        assert_eq!(request.gas, Some(0xc350));
        assert_eq!(request.gas_price, Some(0x4a817c800));
        assert_eq!(request.value, Some(u256("0x0")));
        assert_eq!(request.input.input, Some(bytes("0xaabbccdd")));
        assert_eq!(request.nonce, Some(0x2));
        assert_eq!(request.chain_id, Some(1));
        assert_eq!(request.transaction_type, Some(1));
        assert!(request.max_fee_per_gas.is_none());
        assert!(request.max_priority_fee_per_gas.is_none());
        assert!(request.access_list.is_some());
        let access_list = request.access_list.unwrap().0;
        assert_eq!(access_list.len(), 1);
        assert_eq!(
            access_list[0].address,
            addr("0x5fbdb2315678afecb367f032d93f642f64180aa3")
        );
        assert_eq!(access_list[0].storage_keys.len(), 1);
        assert_eq!(
            access_list[0].storage_keys[0],
            b256("0x0000000000000000000000000000000000000000000000000000000000000000")
        );
    }

    #[test]
    fn deserialize_eip1559_transaction() {
        let json = r#"{
          "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
          "to": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
          "gas": "0xc350",
          "maxFeePerGas": "0x77359400",
          "maxPriorityFeePerGas": "0x3b9aca00",
          "value": "0x0",
          "input": "0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "nonce": "0x5",
          "chainId": "0xaa36a7",
          "type": "0x2",
          "accessList": []
        }"#;

        let request: TransactionRequest =
            serde_json::from_str(json).expect("Failed to deserialize EIP-1559 tx");

        assert_eq!(
            request.from,
            Some(addr("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
        );
        assert_eq!(
            request.to,
            Some(TxKind::Call(addr(
                "0x5fbdb2315678afecb367f032d93f642f64180aa3"
            )))
        );
        assert_eq!(request.gas, Some(0xc350));
        assert_eq!(request.max_fee_per_gas, Some(0x77359400));
        assert_eq!(request.max_priority_fee_per_gas, Some(0x3b9aca00));
        assert_eq!(request.value, Some(u256("0x0")));
        assert_eq!(request.input.input.as_ref().map(|b| b.len()), Some(68)); // Check input length
        assert_eq!(request.nonce, Some(0x5));
        assert_eq!(request.chain_id, Some(11155111)); // Sepolia
        assert_eq!(request.transaction_type, Some(2));
        assert!(request.gas_price.is_none());
        assert!(request.access_list.is_some());
        assert!(request.access_list.unwrap().0.is_empty()); // Access list is present but empty
    }

    #[test]
    fn deserialize_eip4844_transaction() {
        // NOTE: The sidecar fields (blobs, commitments, proofs) are often sent separately
        // from the RPC request for the transaction itself. The TransactionRequest often
        // only includes the `blobVersionedHashes`. This test reflects that common case.
        // If your use case includes flattened sidecar fields in the request JSON, add them here.
        let json = r#"{
            "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "to": "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045",
            "gas": "0x15f90",
            "maxFeePerGas": "0x77359400",
            "maxPriorityFeePerGas": "0x3b9aca00",
            "maxFeePerBlobGas": "0xa",
            "value": "0x0",
            "input": "0x",
            "nonce": "0xa",
            "chainId": "0xaa36a7",
            "type": "0x3",
            "blobVersionedHashes": ["0x01cf3c34d3feed2066b1879d7f33c697554c94761940aa34f4f198709c4ef1d1"],
            "accessList": []
        }"#;
        // "sidecar": ["0x..."] // if blobs are expected directly in the JSON due to flatten

        let request: TransactionRequest =
            serde_json::from_str(json).expect("Failed to deserialize EIP-4844 tx");

        assert_eq!(
            request.from,
            Some(addr("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
        );
        assert_eq!(
            request.to,
            Some(TxKind::Call(addr(
                "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
            )))
        );
        assert_eq!(request.gas, Some(0x15f90));
        assert_eq!(request.max_fee_per_gas, Some(0x77359400));
        assert_eq!(request.max_priority_fee_per_gas, Some(0x3b9aca00));
        assert_eq!(request.max_fee_per_blob_gas, Some(0xa));
        assert_eq!(request.value, Some(u256("0x0")));
        assert_eq!(request.input.input, Some(bytes("0x")));
        assert_eq!(request.nonce, Some(0xa));
        assert_eq!(request.chain_id, Some(11155111)); // Sepolia
        assert_eq!(request.transaction_type, Some(3));
        assert!(request.gas_price.is_none());
        assert!(request.access_list.is_some());
        assert!(request.access_list.unwrap().0.is_empty());
        assert!(request.blob_versioned_hashes.is_some());
        let hashes = request.blob_versioned_hashes.unwrap();
        assert_eq!(hashes.len(), 1);
        assert_eq!(
            hashes[0],
            b256("0x01cf3c34d3feed2066b1879d7f33c697554c94761940aa34f4f198709c4ef1d1")
        );
        assert!(request.sidecar.is_none());
    }

    #[test]
    fn deserialize_eip7702_transaction() {
        // EIP-7702 is new, structure of SignedAuthorization might vary. Using placeholders.
        let json = r#"{
            "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "to": "0x70997970c51812dc3a010c7d01b50e0d17dc79c8",
            "gas": "0x5208",
            "maxFeePerGas": "0x4a817c800",
            "maxPriorityFeePerGas": "0x3b9aca00",
            "value": "0x1",
            "input": "0x",
            "nonce": "0xb",
            "chainId": "0x1",
            "type": "0x4",
            "authorizationList": [
                {
                    "chainId": "0x1",
                    "address": "0xc0ffee254729296a45a3885639AC7E10F9d54979",
                    "nonce": "0x123",
                    "yParity": "0x",
                    "r":"0x",
                    "s":"0x"
                }
            ]
        }"#;

        let request: TransactionRequest =
            serde_json::from_str(json).expect("Failed to deserialize EIP-7702 tx");

        assert_eq!(
            request.from,
            Some(addr("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
        );
        assert_eq!(
            request.to,
            Some(TxKind::Call(addr(
                "0x70997970c51812dc3a010c7d01b50e0d17dc79c8"
            )))
        );
        assert_eq!(request.gas, Some(0x5208));
        assert_eq!(request.max_fee_per_gas, Some(0x4a817c800));
        assert_eq!(request.max_priority_fee_per_gas, Some(0x3b9aca00));
        assert_eq!(request.value, Some(u256("0x1")));
        assert_eq!(request.input.input, Some(bytes("0x")));
        assert_eq!(request.nonce, Some(0xb));
        assert_eq!(request.chain_id, Some(1));
        assert_eq!(request.transaction_type, Some(4));
        assert!(request.gas_price.is_none());
        assert!(request.authorization_list.is_some());
        let auth_list = request.authorization_list.unwrap();
        assert_eq!(auth_list.len(), 1);
        // Add assertions for fields within SignedAuthorization once defined
        assert_eq!(auth_list[0].chain_id, u256("0x1"));
        assert_eq!(
            auth_list[0].address,
            addr("0xc0ffee254729296a45a3885639AC7E10F9d54979")
        );
        assert_eq!(auth_list[0].nonce, 0x123);
    }

    #[test]
    fn deserialize_optional_fields_missing() {
        // Test a minimal EIP-1559 transaction where optional fields are omitted
        // from, value, input, nonce, chainId, accessList are omitted
        let json = r#"{
          "to": "0x5fbdb2315678afecb367f032d93f642f64180aa3",
          "gas": "0xc350",
          "maxFeePerGas": "0x77359400",
          "maxPriorityFeePerGas": "0x3b9aca00",
          "type": "0x2"
        }"#;

        let request: TransactionRequest =
            serde_json::from_str(json).expect("Failed to deserialize minimal EIP-1559 tx");

        assert_eq!(
            request.to,
            Some(TxKind::Call(addr(
                "0x5fbdb2315678afecb367f032d93f642f64180aa3"
            )))
        );
        assert_eq!(request.gas, Some(0xc350));
        assert_eq!(request.max_fee_per_gas, Some(0x77359400));
        assert_eq!(request.max_priority_fee_per_gas, Some(0x3b9aca00));
        assert_eq!(request.transaction_type, Some(2));

        // Check that omitted optional fields are None
        assert!(request.from.is_none());
        assert!(request.value.is_none());
        assert!(request.input.input.is_none()); // Check inner field of flattened struct
        assert!(request.nonce.is_none());
        assert!(request.chain_id.is_none());
        assert!(request.access_list.is_none());
        assert!(request.gas_price.is_none());
    }

    #[test]
    fn deserialize_contract_creation() {
        // Legacy contract creation (to is null/omitted)
        // "to" is omitted for contract creation
        // "input" is contract deployment bytecode
        let json = r#"{
          "from": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
          "gas": "0x14826d",
          "gasPrice": "0x4a817c800",
          "input": "0xa9059cbb00000000000000000000000070997970c51812dc3a010c7d01b50e0d17dc79c80000000000000000000000000000000000000000000000000de0b6b3a7640000",
          "nonce": "0x10"
        }"#;

        let request: TransactionRequest =
            serde_json::from_str(json).expect("Failed to deserialize contract creation tx");

        assert_eq!(
            request.from,
            Some(addr("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266"))
        );
        assert_eq!(request.to, None); // Or Some(TxKind::Create) depending on TxKind impl
        assert_eq!(request.gas, Some(0x14826d));
        assert_eq!(request.gas_price, Some(0x4a817c800));
        assert!(request.input.input.is_some()); // Should have deployment bytecode
        assert_eq!(request.nonce, Some(0x10));
        assert!(request.value.is_none());
        assert!(request.transaction_type.is_none()); // Legacy
    }
}
