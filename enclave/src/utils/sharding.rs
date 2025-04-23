use blahaj::{Share, Sharks};
use hex::{decode as hex_decode, encode as hex_encode};
use thiserror::Error;

const THRESHOLD: u8 = 2;
const TOTAL_SHARES: usize = 2;
const SHARKS: Sharks = Sharks(THRESHOLD);

#[derive(Error, Debug)]
pub enum ShardingError {
    #[error("The share provided is invalid")]
    InvalidShare(String),
    #[error("Number of shares provided is not up to threshold")]
    InsufficientShares(String),
}

pub fn split_secret(secret: Vec<u8>) -> Vec<String> {
    let dealer = SHARKS.dealer(&secret);
    let shares: Vec<Share> = dealer.take(TOTAL_SHARES).collect();
    let shares_bytes: Vec<String> = shares.iter().map(|x| share_to_hex(x)).collect();
    shares_bytes
}

pub fn recover_secret(shares_bytes: Vec<String>) -> Result<Vec<u8>, ShardingError> {
    let shares: Vec<Share> = shares_bytes
        .iter()
        .map(|s| hex_to_share(s))
        .collect::<Result<Vec<_>, _>>()?;

    let secret = SHARKS.recover(shares.as_slice()).map_err(|_| {
        ShardingError::InsufficientShares(
            "Number of shares provided is not up to threshold".to_string(),
        )
    })?;

    Ok(secret)
}

fn share_to_hex(share: &Share) -> String {
    let bytes = Vec::from(share);
    hex_encode(bytes)
}

fn hex_to_share(hex_str: &str) -> Result<Share, ShardingError> {
    let decoded_bytes = hex_decode(hex_str).map_err(|_| {
        ShardingError::InvalidShare("Failed to create share from slice".to_string())
    })?;

    let shard = Share::try_from(decoded_bytes.as_slice())
        .map_err(|_| ShardingError::InvalidShare("The share provided is invalid".to_string()))?;

    Ok(shard)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::generate::generate_seed;

    #[test]
    fn test_split() {
        let seed = generate_seed();

        let shares_bytes: Vec<String> = split_secret(seed.as_bytes().to_vec());

        assert_eq!(shares_bytes.len(), THRESHOLD as usize);

        let secret = recover_secret(shares_bytes).unwrap();

        assert_eq!(secret, seed.as_bytes().to_vec());
    }
}
