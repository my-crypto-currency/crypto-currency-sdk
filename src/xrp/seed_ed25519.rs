use super::Base58Array;

const ED25519_SEED: [u8; 3] = [0x01, 0xe1, 0x4b];
const EXPECTED_LEN: usize = 16;

pub struct SeedED25519 {
    entropy: Vec<u8>,
}

impl SeedED25519 {
    pub fn generate_random() -> Self {
        use ring::rand::*;
        let mut entropy = Vec::with_capacity(16);
        unsafe {
            entropy.set_len(16);
        }
        SystemRandom::new().fill(&mut entropy).unwrap();
        Self {
            entropy: entropy.to_vec(),
        }
    }

    pub fn to_string(&self) -> String {
        let mut result = ED25519_SEED.to_vec();
        result.extend_from_slice(&self.entropy);
        let sha = crate::utils::calc_sha256(result.as_slice());
        let sha_2 = crate::utils::calc_sha256(sha.as_slice());
        let checksum = &sha_2[..4];
        result.extend_from_slice(checksum);
        let result: Base58Array = result.as_slice().into();
        result.into_string()
    }

    pub fn from_phrase(seed_phrase: &str) -> Result<Self, String> {
        let decoded = super::Base58Array::try_decode(seed_phrase)?;
        verify_seed_checksum(decoded.as_slice());

        let without_sum = &decoded[..decoded.len() - 4];

        // println!("decoded: {:?}", without_sum);

        let versions_bytes = &without_sum[..3];

        if versions_bytes != ED25519_SEED {
            return Err("This is not a ED25519 seed".to_string());
        }

        //println!("versions_bytes: {:?}", versions_bytes);

        let entropy = &without_sum[3..];

        if entropy.len() != EXPECTED_LEN {
            return Err(format!(
                "Invalid entropy length {}. Expected {}",
                entropy.len(),
                EXPECTED_LEN,
            ));
        }

        //   println!("payload : {:?}", entropy);

        let result = Self {
            entropy: entropy.to_vec(),
        };

        Ok(result)
    }

    pub fn get_entropy(&self) -> &[u8] {
        &self.entropy
    }
}

fn verify_seed_checksum(decoded: &[u8]) {
    if decoded.len() < 5 {
        panic!("invalid_input_size: decoded data must have length >= 5");
    }

    let sha = crate::utils::calc_sha256(&decoded[..&decoded.len() - 4]);

    let sha_2 = crate::utils::calc_sha256(sha.as_slice());

    let sha_2 = &sha_2[..4];

    let to_verify = &decoded[decoded.len() - 4..];

    assert_eq!(&sha_2[..4], to_verify);
}

#[cfg(test)]
mod tests {
    use crate::xrp::XrpWallet;

    use super::SeedED25519;

    #[test]
    fn test_decode_seed() {
        let seed = SeedED25519::from_phrase("sEd7x5o94W5HuGnpKgnTaDMPk69dffC").unwrap();

        let result = seed.to_string();

        assert_eq!("sEd7x5o94W5HuGnpKgnTaDMPk69dffC", result);
    }

    #[test]
    fn test_generate_random() {
        let src_seed = SeedED25519::generate_random();

        let seed_txt = src_seed.to_string();

        let wallet_src: XrpWallet = src_seed.try_into().unwrap();

        let result_seed = SeedED25519::from_phrase(&seed_txt).unwrap();

        let result_seed_text = result_seed.to_string();

        assert_eq!(seed_txt, result_seed_text);

        let result_wallet: XrpWallet = result_seed.try_into().unwrap();

        assert_eq!(
            wallet_src.get_private_key().as_bytes(),
            result_wallet.get_private_key().as_bytes()
        );
    }
}
