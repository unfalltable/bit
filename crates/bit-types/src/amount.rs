use crate::{Error, Result};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::{fmt, str::FromStr};

pub const MAX_AMOUNT_EXCLUSIVE: u128 = 1u128 << 120;
pub const MAX_SUPPLY_ATOMIC: u128 = 10_240_000_000_000_000_000;

#[derive(Clone, Copy, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Amount(u128);

impl Amount {
    pub const ZERO: Self = Self(0);

    pub fn new(value: u128) -> Result<Self> {
        if value < MAX_AMOUNT_EXCLUSIVE {
            Ok(Self(value))
        } else {
            Err(Error::InvalidAmount)
        }
    }

    pub const fn value(self) -> u128 {
        self.0
    }

    pub const fn to_be_bytes(self) -> [u8; 16] {
        self.0.to_be_bytes()
    }

    pub fn from_be_bytes(bytes: [u8; 16]) -> Result<Self> {
        if bytes[0] != 0 {
            return Err(Error::InvalidAmount);
        }
        Self::new(u128::from_be_bytes(bytes))
    }
}

impl TryFrom<u128> for Amount {
    type Error = Error;
    fn try_from(value: u128) -> Result<Self> {
        Self::new(value)
    }
}

impl From<Amount> for u128 {
    fn from(value: Amount) -> Self {
        value.0
    }
}

impl FromStr for Amount {
    type Err = Error;
    fn from_str(value: &str) -> Result<Self> {
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(Error::InvalidAmount);
        }
        Self::new(value.parse().map_err(|_| Error::InvalidAmount)?)
    }
}

impl fmt::Display for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl fmt::Debug for Amount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Amount({})", self.0)
    }
}

impl Serialize for Amount {
    fn serialize<S: Serializer>(&self, serializer: S) -> core::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Amount {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> core::result::Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn amount_bounds_and_json_are_exact() {
        assert!(MAX_SUPPLY_ATOMIC > i64::MAX as u128);
        let maximum = Amount::new(MAX_AMOUNT_EXCLUSIVE - 1).unwrap();
        assert!(Amount::new(MAX_AMOUNT_EXCLUSIVE).is_err());
        assert_eq!(maximum.to_be_bytes()[0], 0);
        let cap = Amount::new(MAX_SUPPLY_ATOMIC).unwrap();
        assert_eq!(
            serde_json::to_string(&cap).unwrap(),
            "\"10240000000000000000\""
        );
        assert_eq!(
            serde_json::from_str::<Amount>("\"10240000000000000000\"").unwrap(),
            cap
        );
        for invalid in ["10240000000000000000", "1e3", "\"01\"", "\"-1\""] {
            assert!(
                serde_json::from_str::<Amount>(invalid).is_err(),
                "{invalid}"
            );
        }
    }
}
