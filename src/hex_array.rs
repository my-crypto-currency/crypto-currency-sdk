pub struct HexArray(String);

impl HexArray {
    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    pub fn to_string(&self) -> String {
        self.0.clone()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        hex::decode(&self.0).unwrap()
    }
}

impl Into<HexArray> for &'_ [u8] {
    fn into(self) -> HexArray {
        HexArray(hex::encode(self))
    }
}

impl Into<HexArray> for String {
    fn into(self) -> HexArray {
        HexArray(self)
    }
}

#[cfg(test)]
mod tests {
    use super::HexArray;

    #[test]
    fn tests() {
        let src = vec![0x01, 0x02, 0x03, 0x04];
        let hex: HexArray = src.as_slice().into();
        let dest = hex.to_bytes();
        assert_eq!(src, dest);
    }
}
