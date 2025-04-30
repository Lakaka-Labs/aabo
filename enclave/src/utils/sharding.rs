use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use blahaj::{Share, Sharks};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ShardingError {
    #[error("The share provided is invalid: {0}")]
    InvalidShare(String),
    #[error(
        "Number of shares provided ({provided}) is less than the required threshold ({threshold})"
    )]
    InsufficientShares { provided: usize, threshold: u8 },
    #[error("Error when trying to shard data: {0}")]
    ErrorShardingData(String),
    #[error("Could not generate the requested number of shares. Expected: {expected}, Got: {got}")]
    ShareGenerationError { expected: usize, got: usize },
    #[error("Threshold cannot be zero")]
    ZeroThreshold,
    #[error("Total shares must be at least the threshold")]
    SharesLessThanThreshold,
    #[error("Threshold cannot be greater than 255")]
    ThresholdTooLarge,
}

pub fn shard_data(
    secret: Vec<u8>,
    threshold: u8,
    total_shares: usize,
) -> Result<Vec<String>, ShardingError> {
    if threshold == 0 {
        return Err(ShardingError::ZeroThreshold);
    }
    if total_shares < threshold as usize {
        return Err(ShardingError::SharesLessThanThreshold);
    }

    let sharks = Sharks(threshold);
    let dealer = sharks.dealer(&secret);
    let shares: Vec<Share> = dealer.take(total_shares).collect();

    if shares.len() != total_shares {
        return Err(ShardingError::ShareGenerationError {
            expected: total_shares,
            got: shares.len(),
        });
    }

    let encoded_shares: Vec<String> = shares.into_iter().map(|x| share_to_base64(&x)).collect();

    Ok(encoded_shares)
}

pub fn assemble_shard(shares_base64: Vec<String>) -> Result<Vec<u8>, ShardingError> {
    let threshold = shares_base64.len() as u8;
    if threshold == 0 {
        return Err(ShardingError::ZeroThreshold);
    }

    let sharks = Sharks(threshold);
    let shares: Vec<Share> = shares_base64
        .iter()
        .map(|s| base64_to_share(s))
        .collect::<Result<Vec<_>, _>>()?;

    let secret =
        sharks
            .recover(shares.as_slice())
            .map_err(|_| ShardingError::InsufficientShares {
                provided: shares.len(),
                threshold,
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
    fn test_shard_and_full_assembly() {
        let seed = generate_seed().unwrap();
        let threshold = 3;
        let total_share = 5;

        let shares_bytes = shard_data(seed.as_bytes().to_vec(), threshold, total_share).unwrap();

        assert_eq!(shares_bytes.len(), total_share);

        let secret = assemble_shard(shares_bytes).unwrap();
        assert_eq!(secret, seed.as_bytes().to_vec());
    }

    #[test]
    fn test_shard_and_partial_assembly() {
        let seed = generate_seed().unwrap();
        let threshold = 3;
        let total_share = 5;

        let mut shares_bytes =
            shard_data(seed.as_bytes().to_vec(), threshold, total_share).unwrap();
        assert_eq!(shares_bytes.len(), total_share);

        shares_bytes.pop();
        shares_bytes.pop();
        assert_eq!(shares_bytes.len(), total_share - 2);

        let secret = assemble_shard(shares_bytes).unwrap();
        assert_eq!(secret, seed.as_bytes().to_vec());
    }

    #[test]
    fn test_shard_and_insufficient_assembly() {
        let seed = generate_seed().unwrap();
        let threshold = 3;
        let total_share = 5;

        let mut shares_bytes =
            shard_data(seed.as_bytes().to_vec(), threshold, total_share).unwrap();
        assert_eq!(shares_bytes.len(), total_share);

        shares_bytes.pop();
        shares_bytes.pop();
        shares_bytes.pop();
        assert_eq!(shares_bytes.len(), total_share - 3);

        let secret = assemble_shard(shares_bytes).unwrap();
        assert_ne!(secret, seed.as_bytes());
    }
}
