pub struct XrpPublicAddress(Vec<u8>);

impl XrpPublicAddress {
    pub fn as_base58(&self) -> super::Base58Array {
        self.0.as_slice().into()
    }
}

impl Into<XrpPublicAddress> for Vec<u8> {
    fn into(self) -> XrpPublicAddress {
        XrpPublicAddress(self)
    }
}

impl std::fmt::Display for XrpPublicAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let base58 = self.as_base58();
        write!(f, "{}", base58.as_str())
    }
}
