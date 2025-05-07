use alloy::signers::local::{MnemonicBuilder, coins_bip39::English};
use bip39::{Language, Mnemonic};
use ed25519_hd_key::derive_from_path;
use solana_sdk::signature::{Signer as SolSigner, keypair_from_seed};
use std::str::FromStr;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum GenerateError {
    #[error("Error generating polkadot pair from seed")]
    ErrorDerivingPolkadot(String),
    #[error("Error generating evm wallet from seed")]
    ErrorDerivingEVM(String),
    #[error("Error generating solana keypair from seed")]
    ErrorDerivingSolana(String),
    #[error("Error generating seed")]
    ErrorDerivingSeed(String),
}

pub fn generate_seed() -> Result<String, GenerateError> {
    let mnemonic = Mnemonic::generate_in(Language::English, 12)
        .map_err(|e| GenerateError::ErrorDerivingSeed(e.to_string()))?;
    Ok(mnemonic.to_string())
}

pub fn generate_evm_account(seed: &str) -> Result<String, GenerateError> {
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(seed)
        .build()
        .map_err(|_| {
            GenerateError::ErrorDerivingEVM("Failed to create master key from seed".to_string())
        })?;

    Ok(format!("{:?}", wallet.address()))
}

pub fn generate_solana_account(seed: &str) -> Result<String, GenerateError> {
    let derivation_path: &str = "m/44'/501'/0'/0'";

    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed)
        .map_err(|e| GenerateError::ErrorDerivingSolana(e.to_string()))?;
    let seed = mnemonic.to_seed("");

    let derived_seed = derive_from_path(derivation_path, &seed).0;

    let keypair = keypair_from_seed(&derived_seed)
        .map_err(|e| GenerateError::ErrorDerivingSolana(e.to_string()))
        .map_err(|e| GenerateError::ErrorDerivingSolana(e.to_string()))?;

    Ok(keypair.pubkey().to_string())
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

        let evm_address = generate_evm_account(&seed).unwrap();
        assert_eq!(evm_address, "0x58e0fb1aab0b04bd095abcdf34484da47fe9ff77");

        let solana_address = generate_solana_account(&seed).unwrap();
        assert_eq!(
            solana_address,
            "3o4E7oU2XHecn9yDiETnTmVUraBQKLzfnzTnWPgu2RGx"
        );
    }
}
