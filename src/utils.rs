pub fn calc_sha256(input: &[u8]) -> Vec<u8> {
    use ring::digest::{digest, SHA256};
    digest(&SHA256, input).as_ref().to_vec()
}

pub fn calc_sha512(input: &[u8]) -> Vec<u8> {
    use ring::digest::{digest, SHA512};
    digest(&SHA512, input).as_ref().to_vec()
}

pub fn calc_ripemd160(input: &[u8]) -> Vec<u8> {
    use ripemd::{Digest, Ripemd160};
    let mut hasher = Ripemd160::new();
    hasher.update(input);
    hasher.finalize().to_vec()
}
