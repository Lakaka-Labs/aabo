use bip39::{Language, Mnemonic};
use ethers::signers::{MnemonicBuilder, Signer, coins_bip39::English};
use solana_sdk::signature::{keypair_from_seed, Signer as SolSigner};
use sp_core::{Pair, crypto::Ss58Codec, sr25519};
use ed25519_hd_key::{derive_from_path};

const  DERIVATION_PATH : &str = "m/44'/501'/0'/0'";

#[derive(Debug)]
pub enum Error {
    ErrorDerivingPolkadot,
    ErrorDerivingEVM,
    ErrorDerivingSolana,
}

fn generate_seed() -> String {
    let mnemonic = Mnemonic::generate_in(Language::English, 12).unwrap();
    mnemonic.to_string()
}

pub fn generate_polkadot_account(seed: &str) -> Result<String, Error> {
    let pair_result = sr25519::Pair::from_phrase(&seed, None);
    match pair_result {
        Ok((pair, _)) => Ok(pair.public().to_ss58check()),
        Err(_) => Err(Error::ErrorDerivingPolkadot),
    }
}
pub fn generate_evm_account(seed: &str) -> Result<String, Error> {
    let derivation_path = "m/44'/60'/0'/0/0";
    let wallet = MnemonicBuilder::<English>::default()
        .phrase(seed)
        .derivation_path(derivation_path)
        .map_err(|_| Error::ErrorDerivingEVM)?
        .build()
        .map_err(|_| Error::ErrorDerivingEVM)?;
    let address = format!("{:?}", wallet.address());
    Ok(address)
}

pub fn generate_solana_account(seed: &str) -> Result<String, Error> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, seed)
        .map_err(|_| Error::ErrorDerivingSolana)?;
    let seed = mnemonic.to_seed("");

    let derived_seed = derive_from_path(DERIVATION_PATH, &seed).0;

    let keypair = keypair_from_seed(&derived_seed)
        .map_err(|e| format!("Failed to create keypair: {}", e)).map_err(|_| Error::ErrorDerivingSolana)?;

    Ok(keypair.pubkey().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate() {
        let seed = String::from(
            "caution juice atom organ advance problem want pledge someone senior holiday very",
        );
        println!("newly generated seed is {seed}");

        let polkadot_account = generate_polkadot_account(&seed).unwrap();
        assert_eq!(
            polkadot_account,
            "5Gv8YYFu8H1btvmrJy9FjjAWfb99wrhV3uhPFoNEr918utyR"
        );
        let evm_account = generate_evm_account(&seed).unwrap();
        assert_eq!(evm_account, "0x58e0fb1aab0b04bd095abcdf34484da47fe9ff77");

        let solana_account = generate_solana_account(&seed).unwrap();
        assert_eq!(solana_account, "3o4E7oU2XHecn9yDiETnTmVUraBQKLzfnzTnWPgu2RGx");
    }
}
