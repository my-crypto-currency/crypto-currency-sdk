const ED25519_SEED: [u8; 3] = [0x01, 0xe1, 0x4b];

pub struct SeedED25519 {
    entropy: Vec<u8>,
}

impl SeedED25519 {
    pub fn from_phrase(seed_phrase: &str) -> Result<Self, String> {
        const EXPECTED_LEN: usize = 16;
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
    use super::SeedED25519;

    #[test]
    fn test_decode_seed() {
        SeedED25519::from_phrase("sEd7x5o94W5HuGnpKgnTaDMPk69dffC").unwrap();
    }
}
