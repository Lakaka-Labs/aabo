use crate::evm::SigningError;
use alloy::signers::SignerSync;
use alloy::signers::local::PrivateKeySigner;

pub fn sign_message(message: &str, signer: &PrivateKeySigner) -> Result<String, SigningError> {
    // Sign a message.
    let signature = signer
        .sign_message_sync(message.as_bytes())
        .map_err(|e| SigningError::SigningFailed(e.to_string()))?;

    let signature_hex = hex::encode(signature.as_bytes());
    Ok(format!("0x{signature_hex}"))
}

#[cfg(test)]
mod test {
    use crate::evm::sign_message::sign_message;
    use alloy::signers::Signature;
    use alloy::signers::local::PrivateKeySigner;

    #[test]
    fn test_eip1559_transfer() {
        let signer: PrivateKeySigner = "CE75F1A875F2DB7FB064F5DBD302B0C77FFEAA18CC4C314167A5111A04F79AFA" // dummy private key
            .parse()
            .unwrap();

        let message = "lakakadodo";

        let signature_hex = sign_message(message, &signer).unwrap();
        let stripped_hex = signature_hex.strip_prefix("0x").unwrap_or(&signature_hex);
        let signature_bytes = hex::decode(stripped_hex).unwrap();

        let signature: Signature = Signature::from_raw(signature_bytes.as_slice()).unwrap();
        let recovered = signature.recover_address_from_msg(message).unwrap();

        assert_eq!(recovered, signer.address())
    }
}
