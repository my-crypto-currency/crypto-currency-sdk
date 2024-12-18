use super::{Base58Array, XrpPublicKey};

pub struct XrpAddress(Base58Array);

impl XrpAddress {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<Base58Array> for XrpAddress {
    fn from(src: Base58Array) -> Self {
        XrpAddress(src)
    }
}

impl std::fmt::Display for XrpAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl Into<XrpAddress> for &'_ XrpPublicKey {
    fn into(self) -> XrpAddress {
        // 1. SHA-256 Hash
        let public_key_sha256 = self.get_sha256();

        let ripemd160_hash = crate::utils::calc_ripemd160(&public_key_sha256);

        let mut address_bytes = vec![0];
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
}

impl From<XrpPublicKey> for XrpAddress {
    fn from(src: XrpPublicKey) -> Self {
        (&src).into()
    }
}

#[cfg(test)]
mod tests {
    use rust_extensions::hex::HexArray;

    #[test]
    fn test_address_generation() {
        let hex_array: HexArray =
            "ED9434799226374926EDA3B54B1B461B4ABF7237962EAE18528FEA67595397FA32".into();

        let public_key: super::XrpPublicKey = hex_array.into();

        let address: super::XrpAddress = public_key.into();

        assert_eq!(address.as_str(), "rDTXLQ7ZKZVKz33zJbHjgVShjsBnqMBhmN");
    }
}
