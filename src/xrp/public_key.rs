use std::fmt::Display;

use crate::HexArray;

pub struct XrpPublicKey(Vec<u8>);

impl XrpPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn get_sha256(&self) -> Vec<u8> {
        crate::utils::calc_sha256(self.as_bytes())
    }

    pub fn as_base58(&self) -> super::Base58Array {
        self.0.as_slice().into()
    }

    pub fn as_hex(&self) -> HexArray {
        self.0.as_slice().into()
    }
}

impl Into<XrpPublicKey> for Vec<u8> {
    fn into(self) -> XrpPublicKey {
        XrpPublicKey(self)
    }
}

impl Display for XrpPublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hex = self.as_hex();
        write!(f, "{}", hex.as_str())
    }
}
