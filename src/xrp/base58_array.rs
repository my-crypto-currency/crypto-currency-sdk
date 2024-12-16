const BASE58_ALPHABET: &str = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";

pub struct Base58Array(String);

impl Base58Array {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_vec(&self) -> Vec<u8> {
        base_x::decode(BASE58_ALPHABET, self.0.as_str()).unwrap()
    }

    pub fn decode(src: &str) -> Vec<u8> {
        base_x::decode(BASE58_ALPHABET, src).unwrap()
    }

    pub fn try_decode(src: &str) -> Result<Vec<u8>, String> {
        match base_x::decode(BASE58_ALPHABET, src) {
            Ok(result) => Ok(result),
            Err(err) => Err(err.to_string()),
        }
    }
}

impl Into<Base58Array> for &'_ [u8] {
    fn into(self) -> Base58Array {
        let result = base_x::encode(BASE58_ALPHABET, self);
        Base58Array(result)
    }
}

impl Into<Base58Array> for Vec<u8> {
    fn into(self) -> Base58Array {
        let result = base_x::encode(BASE58_ALPHABET, self.as_slice());
        Base58Array(result)
    }
}

impl Into<Base58Array> for &'_ str {
    fn into(self) -> Base58Array {
        let result = base_x::encode(BASE58_ALPHABET, self.as_bytes());
        Base58Array(result)
    }
}

impl std::fmt::Display for Base58Array {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0.as_str())
    }
}
