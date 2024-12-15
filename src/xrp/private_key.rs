use crate::HexArray;

pub struct XrpPrivateKey(Vec<u8>);

impl XrpPrivateKey {
    pub fn from_hex(src: &str) -> Self {
        let from_hex = hex::decode(&src).unwrap();
        Self(from_hex)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_hex(&self) -> HexArray {
        self.0.as_slice().into()
    }

    pub fn as_base58(&self) -> super::Base58Array {
        self.0.as_slice().into()
    }
}

impl Into<XrpPrivateKey> for Vec<u8> {
    fn into(self) -> XrpPrivateKey {
        XrpPrivateKey(self)
    }
}

impl std::fmt::Display for XrpPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = self.as_hex();
        write!(f, "{}", hex.as_str())
    }
}
