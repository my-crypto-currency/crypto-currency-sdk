use super::{Entropy, XrpPrivateKey, XrpPublicAddress, XrpPublicKey};

pub struct XrpWallet {
    pub public_key: XrpPublicKey,
    pub private_key: XrpPrivateKey,
}

impl XrpWallet {
    pub fn generate_ed25519_keypair(entropy: &Entropy) -> Result<Self, String> {
        use ring::signature::{self, KeyPair};

        let raw_priv = entropy.sha512_digest_32();

        let key_pair = signature::Ed25519KeyPair::from_seed_unchecked(&raw_priv)
            .map_err(|err| err.to_string())?;

        let raw_pub = key_pair.public_key().as_ref().to_vec();

        Ok(Self {
            public_key: raw_pub.into(),
            private_key: raw_priv.into(),
        })
        //Ok((raw_priv.into(), raw_pub.into()))
    }

    pub fn get_public_address(&self, is_main_net: bool) -> XrpPublicAddress {
        // 1. SHA-256 Hash
        let public_key_sha256 = self.public_key.get_sha256();

        let ripemd160_hash = crate::utils::calc_ripemd160(&public_key_sha256);

        // 3. Network Byte
        let network_byte: u8 = if is_main_net { 0x00 } else { 0x74 };
        let mut address_bytes = vec![network_byte];
        address_bytes.extend_from_slice(&ripemd160_hash);

        // 4. Double SHA-256 Hash
        let sha256_hash_1 = crate::utils::calc_sha256(address_bytes.as_slice());

        let sha256_hash_2 = crate::utils::calc_sha256(sha256_hash_1.as_slice());

        // 5. Checksum
        let checksum = &sha256_hash_2[..4];

        // 6. Append Checksum
        address_bytes.extend_from_slice(checksum);

        address_bytes.into()
    }

    pub fn sign(&self, message: &str) -> Result<Vec<u8>, String> {
        let key_pair =
            ring::signature::Ed25519KeyPair::from_seed_unchecked(self.private_key.as_bytes())
                .map_err(|err| err.to_string())?;

        let signature = key_pair.sign(message.as_bytes());

        Ok(signature.as_ref().to_vec())
    }

    pub fn is_signature_valid(&self, message: &str, signature: &[u8]) -> bool {
        use ring::signature::{self, UnparsedPublicKey};

        let public_key = UnparsedPublicKey::new(&signature::ED25519, self.public_key.as_bytes());

        public_key.verify(message.as_bytes(), signature).is_ok()
    }
}

#[cfg(test)]
mod test {

    #[test]
    fn test_xrp() {
        use super::super::Entropy;
        use super::XrpWallet;

        let entropy = Entropy::new_random();
        let key_pair = XrpWallet::generate_ed25519_keypair(&entropy).unwrap();

        println!("Public XRP Key: {}", key_pair.public_key);
        println!("Private XRP Key: {}", key_pair.private_key);
        println!("Public XRP address: {}", key_pair.get_public_address(true));

        let message = "This is the message to be signed.";

        let signature = key_pair.sign(message).unwrap();

        assert!(key_pair.is_signature_valid(message, &signature));
    }
}
