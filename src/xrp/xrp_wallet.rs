use super::{SeedED25519, XrpAddress, XrpPrivateKey, XrpPublicKey};

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

    pub fn get_public_address(&self) -> XrpAddress {
        self.get_pubic_key().into()
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

        let key_pair = ring::signature::Ed25519KeyPair::from_seed_unchecked(raw_private_key)
            .map_err(|itm| format!("Failed to create key pair. Err: {}", itm))?;

        let public_key_raw = key_pair.public_key().as_ref();

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
            xrp_wallet.get_public_address().as_str(),
            "rDXQD4zC5LjwB7wAoJMn7aEk8dPRHHtUCu"
        );
    }

    #[test]
    fn test_restore_other_testnet_wallet() {
        let seed = SeedED25519::from_phrase("sEd7hgMeGgKiKZQ74imayaNGcx62tg4").unwrap();
        let xrp_wallet: XrpWallet = seed.try_into().unwrap();

        assert_eq!(
            "EDF28A5980EA4A8E5DE51A9520782C3CC7C89F7112990C3871AC73283EDAFEACA2",
            xrp_wallet.get_private_key().to_string().as_str()
        );
        assert_eq!(
            "EDCEDF86F8A6C4C1AA3CCF92F36E6C7524471E0A43B2A570F03FBB69039B94073B",
            xrp_wallet.get_pubic_key().to_string().as_str()
        );

        assert_eq!(
            xrp_wallet.get_public_address().as_str(),
            "rJj4Nvu8qghDL8bwcGKqPyMaDBV8Vdrakm"
        );
    }
}
