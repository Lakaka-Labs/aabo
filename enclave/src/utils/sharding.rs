use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use blahaj::{Share, Sharks};
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
    let shares_bytes: Vec<String> = shares.iter().map(|x| share_to_base64(x)).collect();
    shares_bytes
}

pub fn recover_secret(shares_bytes: Vec<String>) -> Result<Vec<u8>, ShardingError> {
    let shares: Vec<Share> = shares_bytes
        .iter()
        .map(|s| base64_to_share(s))
        .collect::<Result<Vec<_>, _>>()?;

    let secret = SHARKS.recover(shares.as_slice()).map_err(|_| {
        ShardingError::InsufficientShares(
            "Number of shares provided is not up to threshold".to_string(),
        )
    })?;

    Ok(secret)
}

fn share_to_base64(share: &Share) -> String {
    let bytes = Vec::from(share);
    BASE64.encode(bytes)
}

fn base64_to_share(base64_str: &str) -> Result<Share, ShardingError> {
    let decoded_bytes = BASE64.decode(base64_str).map_err(|_| {
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
