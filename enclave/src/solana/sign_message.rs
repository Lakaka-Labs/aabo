use crate::solana::SigningError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use solana_sdk::signature::Keypair;
use solana_sdk::signer::Signer;

pub fn sign_message(message: &[u8], keypair: Keypair) -> Result<String, SigningError> {
    let signature = keypair.sign_message(message);

    let signature_base64 = BASE64.encode(signature.as_ref());

    Ok(signature_base64)
}

#[cfg(test)]
mod test {

}
