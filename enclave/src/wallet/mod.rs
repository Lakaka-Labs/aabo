use crate::utils::encryption::hybrid::hybrid_encrypt;
use crate::utils::encryption::kms::{AWSEncryptConfig, Encrypt};
use crate::utils::generate::{generate_evm_account, generate_seed, generate_solana_account};
use crate::utils::sharding::{assemble_shard, shard_data};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum WalletError {
    #[error("Error generating address")]
    ErrorGeneratingAddress(String),
    #[error("Error sharding seed phrase")]
    ErrorShardingSeed(String),
    #[error("Error encrypting shard")]
    ErrorEncryptingShard(String),
    #[error("Number of shares provided is less than the required")]
    InsufficientShares(String),
    #[error("Error occurred while trying to assemble sharded shares")]
    ErrorAssemblingShares(String),
}

#[derive(Serialize, Deserialize, Debug)]
pub struct EncryptedShare {
    #[serde(rename = "publicKey")]
    public_key: String,
    #[serde(rename = "encryptedShare")]
    encrypted_share: String,
    #[serde(rename = "ephemeralPublicKey")]
    ephemeral_public_key: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Wallet {
    address: String,
    shares: Vec<String>,
    #[serde(rename = "kmsShare")]
    encrypted_kms_share: Option<String>,
    #[serde(rename = "encryptedShares")]
    encrypted_shares: Vec<EncryptedShare>,
}

impl Wallet {
    // Assuming the first share is always reserved for KMS if KMS is used.
    // If shares can be used interchangeably, this logic might need adjustment.
    fn encrypt_kms_share<T: Encrypt>(&mut self, config: &T) -> Result<(), WalletError> {
        let share_to_encrypt = self.shares.get(0).ok_or_else(|| {
            WalletError::InsufficientShares(
                "Cannot encrypt KMS share: No shares available.".to_string(),
            )
        })?;

        self.encrypted_kms_share = Some(
            config
                .encrypt(share_to_encrypt.clone().into_bytes())
                .map_err(|e| {
                    WalletError::ErrorEncryptingShard(format!("Error encrypting KMS share: {}", e))
                })?,
        );

        Ok(())
    }

    fn encrypt_other_shares(&mut self, public_keys: Vec<String>) -> Result<(), WalletError> {
        let starting_share_index = if self.encrypted_kms_share.is_some() {
            1
        } else {
            0
        };

        let available_shares_count = self.shares.len().saturating_sub(starting_share_index);
        if available_shares_count < public_keys.len() {
            return Err(WalletError::InsufficientShares(format!(
                "Insufficient shares ({}) available for the {} public keys provided (starting from index {}).",
                available_shares_count,
                public_keys.len(),
                starting_share_index
            )));
        }

        let shares_for_hybrid = &self.shares[starting_share_index..]; // Slice of shares to use

        for (share, pk) in shares_for_hybrid.iter().zip(public_keys.iter()) {
            let (ephemeral_public_key, encrypted_share) =
                hybrid_encrypt(pk.to_string(), share.as_bytes()).map_err(|e| {
                    WalletError::ErrorEncryptingShard(format!(
                        "Error encrypting share for pk {}: {}",
                        pk, e
                    ))
                })?;

            self.encrypted_shares.push(EncryptedShare {
                public_key: pk.to_string(), // Dereference pk as it's &&str from iter()
                encrypted_share,
                ephemeral_public_key,
            });
        }

        Ok(())
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Network {
    Ethereum,
    Solana,
}
impl Network {
    fn create_and_split_seed(
        threshold: u8,
        total_shares: usize,
    ) -> Result<(String, Vec<String>), WalletError> {
        let seed = generate_seed();
        let shares = shard_data(seed.clone().into_bytes(), threshold, total_shares)
            .map_err(|e| WalletError::ErrorShardingSeed(e.to_string()))?;

        Ok((seed, shares))
    }

    fn generate_address(&self, seed: String) -> Result<String, WalletError> {
        match self {
            Network::Ethereum => generate_evm_account(&seed)
                .map_err(|e| WalletError::ErrorGeneratingAddress(e.to_string())),
            Network::Solana => generate_solana_account(&seed)
                .map_err(|e| WalletError::ErrorGeneratingAddress(e.to_string())),
        }
    }

    pub fn create(&self, threshold: u8, total_shares: usize) -> Result<Wallet, WalletError> {
        let (seed, shares) = Self::create_and_split_seed(threshold, total_shares)?;

        if shares.len() != total_shares {
            return Err(WalletError::InsufficientShares(
                "Number of shares provided is less than the required".to_string(),
            ));
        }

        Ok(Wallet {
            address: self.generate_address(seed)?,
            shares,
            encrypted_kms_share: None,
            encrypted_shares: Vec::new(),
        })
    }

    pub fn create_with_kms<T: Encrypt>(
        &self,
        threshold: u8,
        mut total_shares: usize,
        config: &T,
    ) -> Result<Wallet, WalletError> {
        total_shares += 1;
        let mut wallet = self.create(threshold, total_shares)?;
        wallet.encrypt_kms_share(config)?;
        Ok(wallet)
    }

    pub fn create_encrypted_shares(
        &self,
        threshold: u8,
        public_keys: Vec<String>,
    ) -> Result<Wallet, WalletError> {
        let mut wallet = self.create(threshold, public_keys.len())?;
        wallet.encrypt_other_shares(public_keys)?;
        Ok(wallet)
    }

    pub fn create_encrypted_shares_with_kms<T: Encrypt>(
        &self,
        threshold: u8,
        public_keys: Vec<String>,
        config: &T,
    ) -> Result<Wallet, WalletError> {
        let mut wallet = self.create(threshold, public_keys.len() + 1)?;
        wallet.encrypt_kms_share(config)?;
        wallet.encrypt_other_shares(public_keys)?;
        Ok(wallet)
    }

    // No of shares provided would be used as threshold
    pub fn reassemble_seed(shares: Vec<String>) -> Result<String, WalletError> {
        let seed_byte = assemble_shard(shares)
            .map_err(|e| WalletError::ErrorAssemblingShares(e.to_string()))?;

        let seed = match String::from_utf8(seed_byte) {
            Ok(s) => s,
            Err(_) => Err(WalletError::ErrorAssemblingShares(
                "error assembling seed phrase, this could be caused by insufficient threshold"
                    .to_string(),
            ))?,
        };

        Ok(seed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::encryption::kms::MockEncrypt;
    use aes_gcm::aead::OsRng;
    use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
    use k256::{PublicKey, SecretKey};

    // --- Basic Network and Wallet Creation Tests ---
    #[test]
    fn test_create_and_split_seed_success() {
        let threshold = 2;
        let total_shares = 3;
        let result = Network::create_and_split_seed(threshold, total_shares);

        assert!(result.is_ok());
        let (seed, shares) = result.unwrap();

        assert!(!seed.is_empty());
        assert_eq!(shares.len(), total_shares,);
        for share in shares {
            assert!(!share.is_empty());
        }
    }

    #[test]
    fn test_create_and_split_seed_error_threshold_too_high() {
        let threshold = 4;
        let total_shares = 3;
        let result = Network::create_and_split_seed(threshold, total_shares);

        assert!(result.is_err());
        match result.err().unwrap() {
            WalletError::ErrorShardingSeed(_) => {}
            _ => panic!("Expected ErrorShardingSeed"),
        }
    }

    #[test]
    fn test_create_wallet_success_ethereum() {
        let threshold = 2;
        let total_shares = 3;
        let network = Network::Ethereum;
        let result = network.create(threshold, total_shares);

        assert!(result.is_ok());
        let wallet = result.unwrap();

        assert!(wallet.address.starts_with("0x"));
        assert_eq!(wallet.shares.len(), total_shares);
        assert!(wallet.encrypted_kms_share.is_none());
        assert!(wallet.encrypted_shares.is_empty());
        assert!(!wallet.shares.iter().any(|s| s.is_empty()));
    }

    #[test]
    fn test_create_wallet_success_solana() {
        let threshold = 2;
        let total_shares = 3;
        let network = Network::Solana;
        let result = network.create(threshold, total_shares);

        assert!(result.is_ok());
        let wallet = result.unwrap();

        assert!(wallet.address.len() >= 32 && wallet.address.len() <= 44);
        assert_eq!(wallet.shares.len(), total_shares);
        assert!(wallet.encrypted_kms_share.is_none());
        assert!(wallet.encrypted_shares.is_empty());
        assert!(!wallet.shares.iter().any(|s| s.is_empty()));
    }

    #[test]
    fn test_create_wallet_error_sharding() {
        let threshold = 5;
        let total_shares = 3;
        let network = Network::Ethereum;
        let result = network.create(threshold, total_shares);

        assert!(result.is_err());
        match result.err().unwrap() {
            WalletError::ErrorShardingSeed(_) => {}
            e => panic!("Expected ErrorShardingSeed, got {:?}", e),
        }
    }

    // --- Reassembly Tests ---

    #[test]
    fn test_reassemble_seed_success() {
        let threshold = 2;
        let total_shares = 3;
        let (original_seed, shares) = Network::create_and_split_seed(threshold, total_shares)
            .expect("Setup failed: Could not create/split seed");

        // Use exactly the threshold number of shares
        let shares_to_reassemble = shares.into_iter().take(threshold as usize).collect();
        let result = Network::reassemble_seed(shares_to_reassemble);

        assert!(result.is_ok());
        let reassembled_seed = result.unwrap();
        assert_eq!(reassembled_seed, original_seed,);
    }

    #[test]
    fn test_reassemble_seed_error_insufficient_shares() {
        let threshold = 3;
        let total_shares = 5;
        let (_original_seed, shares) = Network::create_and_split_seed(threshold, total_shares)
            .expect("Setup failed: Could not create/split seed");

        // Use fewer than the threshold number of shares
        let shares_to_reassemble = shares.into_iter().take((threshold - 1) as usize).collect();
        let result = Network::reassemble_seed(shares_to_reassemble);

        assert!(result.is_err());
        match result.err().unwrap() {
            WalletError::ErrorAssemblingShares(_) => {} // Expected error
            e => panic!("Expected ErrorAssemblingShares, got {:?}", e),
        }
    }

    #[test]
    fn test_reassemble_seed_error_corrupted_share() {
        let threshold = 2;
        let total_shares = 3;
        let (_original_seed, mut shares) = Network::create_and_split_seed(threshold, total_shares)
            .expect("Setup failed: Could not create/split seed");

        // Corrupt one share slightly (e.g., change a character)
        if !shares.is_empty() && !shares[0].is_empty() {
            let mut corrupted_share_bytes = shares[0].as_bytes().to_vec();
            corrupted_share_bytes[0] = corrupted_share_bytes[0].wrapping_add(1); // Simple corruption
            shares[0] = String::from_utf8_lossy(&corrupted_share_bytes).to_string(); // May not be valid UTF8, but sharding likely works on bytes
        } else {
            panic!("Cannot corrupt empty share");
        }

        // Use the threshold number of shares, including the corrupted one
        let shares_to_reassemble = shares.into_iter().take(threshold as usize).collect();
        let result = Network::reassemble_seed(shares_to_reassemble);

        assert!(result.is_err());
        match result.err().unwrap() {
            WalletError::ErrorAssemblingShares(_) => {}
            e => panic!(
                "Expected ErrorAssemblingShares due to corruption, got {:?}",
                e
            ),
        }
    }

    // --- Wallet Method Tests ---

    #[test]
    fn test_encrypt_kms_share_success() {
        let mut config = MockEncrypt::new();

        let network = Network::Ethereum;
        // Create a wallet directly to control its initial state
        let (_seed, shares) = Network::create_and_split_seed(2, 3).unwrap();
        let mut wallet = Wallet {
            address: network.generate_address(_seed).unwrap(),
            shares: shares.clone(),
            encrypted_kms_share: None,
            encrypted_shares: Vec::new(),
        };

        assert!(wallet.encrypted_kms_share.is_none());
        config
            .expect_encrypt()
            .times(1)
            .returning(|data| Ok(BASE64.encode(data)));
        let result = wallet.encrypt_kms_share(&config);

        assert!(
            result.is_ok(),
            "encrypt_kms_share failed: {:?}",
            result.err()
        );
        assert!(wallet.encrypted_kms_share.is_some());
        // The encrypted data is usually base64 encoded, check it's not empty
        assert!(!wallet.encrypted_kms_share.as_ref().unwrap().is_empty());
    }

    #[test]
    fn test_encrypt_kms_share_error_no_shares() {
        let mut config = MockEncrypt::new();
        config
            .expect_encrypt()
            .times(0)
            .returning(|data| Ok(BASE64.encode(data)));

        let mut wallet = Wallet {
            address: "0x123".to_string(),
            shares: Vec::new(), // NO shares
            encrypted_kms_share: None,
            encrypted_shares: Vec::new(),
        };

        let result = wallet.encrypt_kms_share(&config);

        assert!(result.is_err());
        match result.err().unwrap() {
            WalletError::InsufficientShares(_) => {} // Expected error
            e => panic!("Expected InsufficientShares, got {:?}", e),
        }
        assert!(wallet.encrypted_kms_share.is_none()); // Should remain None
    }

    #[test]
    fn test_encrypt_other_shares_error_no_shares() {
        let mut wallet = Wallet {
            address: "0x123".to_string(),
            shares: Vec::new(), // NO shares
            encrypted_kms_share: None,
            encrypted_shares: Vec::new(),
        };
        let test_secret_key_1 = SecretKey::random(&mut OsRng);
        let test_public_key_1 = BASE64.encode(test_secret_key_1.public_key().to_sec1_bytes());

        let public_keys = vec![test_public_key_1];

        let result = wallet.encrypt_other_shares(public_keys);
        assert!(result.is_err());
        match result.err().unwrap() {
            WalletError::InsufficientShares(_) => {} // Expected error
            e => panic!("Expected InsufficientShares, got {:?}", e),
        }
        assert!(wallet.encrypted_shares.is_empty()); // Should remain empty
    }

    // --- Combined Creation Method Tests ---

    #[test]
    fn test_create_with_kms_success() {
        let mut config = MockEncrypt::new();
        config
            .expect_encrypt()
            .times(1)
            .returning(|data| Ok(BASE64.encode(data)));

        let threshold = 2;
        let requested_total_shares = 2; 
        let network = Network::Ethereum;

        let result = network.create_with_kms(threshold, requested_total_shares, &config);

        assert!(result.is_ok(), "create_with_kms failed: {:?}", result.err());
        let wallet = result.unwrap();

        assert!(wallet.address.starts_with("0x"));
        assert_eq!(wallet.shares.len(), requested_total_shares + 1);
        assert!(wallet.encrypted_kms_share.is_some());
        assert!(!wallet.encrypted_kms_share.as_ref().unwrap().is_empty());
        assert!(wallet.encrypted_shares.is_empty()); 
    }

    #[test]
    fn test_create_encrypted_shares_current_behaviour() {
        let threshold = 2;

        let test_secret_key_1 = SecretKey::random(&mut OsRng);
        let test_secret_key_2 = SecretKey::random(&mut OsRng);
        let test_public_key_1 = BASE64.encode(test_secret_key_1.public_key().to_sec1_bytes());
        let test_public_key_2 = BASE64.encode(test_secret_key_2.public_key().to_sec1_bytes());
        let public_keys = vec![test_public_key_1.clone(), test_public_key_2.clone()];

        let network = Network::Solana;

        let result = network.create_encrypted_shares(threshold, public_keys.clone()); 

        // If `encrypt_other_shares` were fixed, the assertions would be:
        assert!(result.is_ok());
        let wallet = result.unwrap();
        assert!(wallet.address.len() >= 32 && wallet.address.len() <= 44);
        assert_eq!(wallet.shares.len(), public_keys.len()); 
        assert!(wallet.encrypted_kms_share.is_none());
        assert_eq!(wallet.encrypted_shares.len(), public_keys.len());
        assert_eq!(wallet.encrypted_shares[0].public_key, test_public_key_1);
        assert_eq!(wallet.encrypted_shares[1].public_key, test_public_key_2);
    }

    #[test]
    fn test_create_encrypted_shares_with_kms_current_behaviour() {
        let mut config = MockEncrypt::new();
        config
            .expect_encrypt()
            .times(1)
            .returning(|data| Ok(BASE64.encode(data)));

        let threshold = 2;

        let test_secret_key_1 = SecretKey::random(&mut OsRng);
        let test_public_key_1 = BASE64.encode(test_secret_key_1.public_key().to_sec1_bytes());

        let public_keys = vec![test_public_key_1.clone()]; // Use one PK for simplicity
        let network = Network::Ethereum;

        let result =
            network.create_encrypted_shares_with_kms(threshold, public_keys.clone(), &config);

        // If `encrypt_other_shares` were fixed, the assertions would be:
        assert!(result.is_ok());
        let wallet = result.unwrap();
        assert!(wallet.address.starts_with("0x"));
        assert_eq!(wallet.shares.len(), public_keys.len() + 1);
        assert!(wallet.encrypted_kms_share.is_some());
        assert!(!wallet.encrypted_kms_share.as_ref().unwrap().is_empty());
        assert_eq!(wallet.encrypted_shares.len(), public_keys.len());
        assert_eq!(wallet.encrypted_shares[0].public_key, test_public_key_1);
        assert!(!wallet.encrypted_shares[0].encrypted_share.is_empty());
    }
}
