pub struct Base58Array(String);

impl Base58Array {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Into<Base58Array> for &'_ [u8] {
    fn into(self) -> Base58Array {
        let result = base_x::encode(super::BASE58_ALPHABET, self);
        Base58Array(result)
    }
}
