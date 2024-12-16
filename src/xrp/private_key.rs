use std::fmt::Debug;

use rust_extensions::hex::HexArray;

pub struct XrpPrivateKey(Vec<u8>);

impl XrpPrivateKey {
    pub fn to_string(&self) -> HexArray {
        HexArray::from_slice_uppercase(self.0.as_slice())
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Into<XrpPrivateKey> for Vec<u8> {
    fn into(self) -> XrpPrivateKey {
        XrpPrivateKey(self)
    }
}

impl std::fmt::Display for XrpPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

impl Debug for XrpPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("XrpPrivateKey").field(&self.0).finish()
    }
}
