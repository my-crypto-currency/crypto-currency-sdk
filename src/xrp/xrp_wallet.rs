use crate::xrp::Base58Array;

use super::{SeedED25519, XrpPrivateKey, XrpPublicAddress, XrpPublicKey};

pub struct XrpWallet {
    public_key: XrpPublicKey,
    private_key: XrpPrivateKey,
}

impl XrpWallet {
    pub fn from_seed(seed: SeedED25519) -> Result<Self, String> {
        let wallet: Self = (&seed).try_into()?;
        Ok(wallet)
    }

    pub fn get_pubic_key(&self) -> &XrpPublicKey {
        &self.public_key
    }

    pub fn get_private_key(&self) -> &XrpPrivateKey {
        &self.private_key
    }

    pub fn get_public_address(&self, is_main_net: bool) -> XrpPublicAddress {
        // 1. SHA-256 Hash
        let public_key_sha256 = self.get_pubic_key().get_sha256();

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

        let base58: Base58Array = address_bytes.into();

        base58.into()
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

impl TryInto<XrpWallet> for &'_ SeedED25519 {
    type Error = String;
    fn try_into(self) -> Result<XrpWallet, Self::Error> {
        use ring::signature::KeyPair;
        let sha_512 = crate::utils::calc_sha512(self.get_entropy());

        let raw_private_key = &sha_512[0..32];

        //let hex = HexArray::from_slice_uppercase(raw_private_key);
        //let private_key = format!("EB{}", hex.as_str());

        let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(raw_private_key)
            .map_err(|itm| format!("Failed to create key pair. Err: {}", itm))?;

        let public_key_raw = key_pair.public_key().as_ref();

        //       println!("Public Key: {:?}", public_key_raw);

        let mut private_key = Vec::with_capacity(raw_private_key.len() + 1);
        private_key.push(0xed);
        private_key.extend_from_slice(raw_private_key);

        let mut public_key = Vec::with_capacity(public_key_raw.len() + 1);
        public_key.push(0xed);
        public_key.extend_from_slice(public_key_raw);

        let result = XrpWallet {
            private_key: private_key.into(),
            public_key: public_key.into(),
        };

        Ok(result)
    }
}

impl TryInto<XrpWallet> for SeedED25519 {
    type Error = String;
    fn try_into(self) -> Result<XrpWallet, Self::Error> {
        (&self).try_into()
    }
}
#[cfg(test)]
mod test {

    use crate::xrp::SeedED25519;

    use super::XrpWallet;

    /// Test the generation of a new random wallet. Credentials are generated using xrpls.js library and tested here
    #[test]
    fn test_restore_testnet_wallet() {
        let seed = SeedED25519::from_phrase("sEd7x5o94W5HuGnpKgnTaDMPk69dffC").unwrap();
        let xrp_wallet: XrpWallet = seed.try_into().unwrap();

        assert_eq!(
            "EDB4CD7A36680067FE8B1EAB77D62263AAE55E4A67BEB817CCCEF23AAD748FEED3",
            xrp_wallet.get_private_key().to_string().as_str()
        );
        assert_eq!(
            "ED5AA99432D9A23559FE300212117FBCB9E2A01AD8382DF170D7660510E1249A7B",
            xrp_wallet.get_pubic_key().to_string().as_str()
        );

        assert_eq!(
            xrp_wallet.get_public_address(false).as_str(),
            "rDXQD4zC5LjwB7wAoJMn7aEk8dPRHHtUCu"
        );
    }
}
