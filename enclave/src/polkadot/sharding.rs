use blahaj::{Share, Sharks};

const THRESHOLD: u8 = 2;
const TOTAL_SHARES: usize = 3;
const SHARKS: Sharks = Sharks(THRESHOLD);

pub enum Error {
    InvalidShare,
    InsufficientShares,
}

pub fn split_secret(secret: &str) -> Vec<Vec<u8>> {
    let dealer = SHARKS.dealer(secret.as_bytes());
    let shares: Vec<Share> = dealer.take(TOTAL_SHARES).collect();
    let shares_bytes: Vec<Vec<u8>> = shares.iter().map(|x| Vec::from(x)).collect();
    shares_bytes
}

pub fn recover_secret(shares_bytes: Vec<Vec<u8>>) -> Result<Vec<u8>, Error> {
    let shares: Vec<Share> = shares_bytes
        .iter()
        .map(|s| Share::try_from(s.as_slice()).map_err(|_| Error::InvalidShare))
        .collect::<Result<Vec<_>, _>>()?;

    let secret = SHARKS
        .recover(shares.as_slice())
        .map_err(|_| Error::InsufficientShares)?;

    Ok(secret)
}


#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    
    #[test]
    fn test_split() {
        let seed = String::from(
            "caution juice atom organ advance problem want pledge someone senior holiday very",
        );

        let mut shares_bytes: Vec<Vec<u8>> = split_secret(&seed);

        let random_index = rand::thread_rng().gen_range(0..3);
        shares_bytes.remove(random_index);

        assert_eq!(shares_bytes.len(), TOTAL_SHARES - 1);

        let secret_result = recover_secret(shares_bytes);

        match secret_result {
            Ok(secret) => {
                assert_eq!(String::from_utf8(secret).unwrap(), seed);
            }
            Err(_) => {
                panic!()
            }
        }
    }
}
