use bip39::{Language, Mnemonic};
use ed25519_hd_key::derive_from_path;
use ethers::core::k256::ecdsa::SigningKey;
use ethers::prelude::Wallet;
use ethers::signers::{MnemonicBuilder, Signer, coins_bip39::English};
use solana_sdk::signature::{Keypair, Signer as SolSigner, keypair_from_seed};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GenerateError {
    #[error("Error generating polkadot pair from seed")]
    ErrorDerivingPolkadot(String),
    #[error("Error generating evm wallet from seed")]
    ErrorDerivingEVM(String),
    #[error("Error generating solana keypair from seed")]
    ErrorDerivingSolana(String),
}

pub fn generate_seed() -> String {
    let mnemonic = Mnemonic::generate_in(Language::English, 12).unwrap();
    mnemonic.to_string()
}

pub fn generate_evm_account(seed: &str) -> Result<Wallet<SigningKey>, GenerateError> {
    let derivation_path = "m/44'/60'/0'/0/0";
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(seed)
        .derivation_path(derivation_path)
        .map_err(|e| GenerateError::ErrorDerivingEVM(e.to_string()))?
        .build()
        .map_err(|e| GenerateError::ErrorDerivingEVM(e.to_string()))?;
    Ok(wallet)
}

pub fn generate_solana_account(seed: &str) -> Result<Keypair, GenerateError> {
    let derivation_path: &str = "m/44'/501'/0'/0'";

    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed)
        .map_err(|e| GenerateError::ErrorDerivingSolana(e.to_string()))?;
    let seed = mnemonic.to_seed("");

    let derived_seed = derive_from_path(derivation_path, &seed).0;

    let keypair = keypair_from_seed(&derived_seed)
        .map_err(|e| GenerateError::ErrorDerivingSolana(e.to_string()))
        .map_err(|e| GenerateError::ErrorDerivingSolana(e.to_string()))?;

    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        // Test Seed
        let seed = String::from(
            "caution juice atom organ advance problem want pledge someone senior holiday very",
        );

        let evm_account = generate_evm_account(&seed).unwrap();
        assert_eq!(
            format!("{:?}", evm_account.address()),
            "0x58e0fb1aab0b04bd095abcdf34484da47fe9ff77"
        );

        let solana_account = generate_solana_account(&seed).unwrap();
        assert_eq!(
            solana_account.pubkey().to_string(),
            "3o4E7oU2XHecn9yDiETnTmVUraBQKLzfnzTnWPgu2RGx"
        );
    }
}
