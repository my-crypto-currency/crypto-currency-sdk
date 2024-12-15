use ring::rand::{SecureRandom, SystemRandom};

pub struct Entropy(ripple_address_codec::Entropy);

impl Entropy {
    pub fn new_random() -> Self {
        let mut entropy = [0u8; 16];
        SystemRandom::new().fill(&mut entropy).unwrap();
        Self(entropy)
    }

    pub fn sha512_digest_32(&self) -> Vec<u8> {
        use ring::digest::{digest, SHA512};
        digest(&SHA512, &self.0).as_ref()[..32].to_vec()
    }
}

impl Into<Entropy> for ripple_address_codec::Entropy {
    fn into(self) -> Entropy {
        Entropy(self)
    }
}
