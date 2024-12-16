use super::Base58Array;

pub struct XrpPublicAddress(Base58Array);

impl XrpPublicAddress {
    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl From<Base58Array> for XrpPublicAddress {
    fn from(src: Base58Array) -> Self {
        XrpPublicAddress(src)
    }
}

impl std::fmt::Display for XrpPublicAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}
