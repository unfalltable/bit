use crate::{Error, Result};

pub(crate) struct Writer(Vec<u8>);

impl Writer {
    pub(crate) fn new() -> Self {
        Self(Vec::new())
    }
    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
    pub(crate) fn array(&mut self, len: usize) {
        self.head(4, len as u64);
    }
    pub(crate) fn uint(&mut self, value: u64) {
        self.head(0, value);
    }
    pub(crate) fn bytes(&mut self, value: &[u8]) {
        self.head(2, value.len() as u64);
        self.0.extend_from_slice(value);
    }
    pub(crate) fn text(&mut self, value: &str) {
        self.head(3, value.len() as u64);
        self.0.extend_from_slice(value.as_bytes());
    }
    pub(crate) fn boolean(&mut self, value: bool) {
        self.0.push(if value { 0xf5 } else { 0xf4 });
    }
    pub(crate) fn null(&mut self) {
        self.0.push(0xf6);
    }
    fn head(&mut self, major: u8, value: u64) {
        let prefix = major << 5;
        match value {
            0..=23 => self.0.push(prefix | value as u8),
            24..=0xff => self.0.extend_from_slice(&[prefix | 24, value as u8]),
            0x100..=0xffff => {
                self.0.push(prefix | 25);
                self.0.extend_from_slice(&(value as u16).to_be_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.0.push(prefix | 26);
                self.0.extend_from_slice(&(value as u32).to_be_bytes());
            }
            _ => {
                self.0.push(prefix | 27);
                self.0.extend_from_slice(&value.to_be_bytes());
            }
        }
    }
}

pub(crate) struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }
    pub(crate) fn finish(self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::InvalidCbor("trailing bytes"))
        }
    }
    pub(crate) fn array(&mut self) -> Result<usize> {
        let (major, value) = self.head()?;
        if major != 4 {
            return Err(Error::InvalidCbor("expected array"));
        }
        usize::try_from(value).map_err(|_| Error::InvalidCbor("array too large"))
    }
    pub(crate) fn uint(&mut self) -> Result<u64> {
        let (major, value) = self.head()?;
        if major == 0 {
            Ok(value)
        } else {
            Err(Error::InvalidCbor("expected unsigned integer"))
        }
    }
    pub(crate) fn bytes(&mut self) -> Result<Vec<u8>> {
        let (major, len) = self.head()?;
        if major != 2 {
            return Err(Error::InvalidCbor("expected byte string"));
        }
        Ok(self
            .take(usize::try_from(len).map_err(|_| Error::InvalidCbor("byte string too large"))?)?
            .to_vec())
    }
    pub(crate) fn text(&mut self) -> Result<String> {
        let (major, len) = self.head()?;
        if major != 3 {
            return Err(Error::InvalidCbor("expected text"));
        }
        let raw =
            self.take(usize::try_from(len).map_err(|_| Error::InvalidCbor("text too large"))?)?;
        String::from_utf8(raw.to_vec()).map_err(|_| Error::InvalidCbor("invalid UTF-8"))
    }
    pub(crate) fn boolean(&mut self) -> Result<bool> {
        match self.byte()? {
            0xf4 => Ok(false),
            0xf5 => Ok(true),
            _ => Err(Error::InvalidCbor("expected boolean")),
        }
    }
    pub(crate) fn nullable<T>(
        &mut self,
        parse: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<Option<T>> {
        if self.peek()? == 0xf6 {
            self.offset += 1;
            Ok(None)
        } else {
            parse(self).map(Some)
        }
    }
    fn peek(&self) -> Result<u8> {
        self.bytes
            .get(self.offset)
            .copied()
            .ok_or(Error::InvalidCbor("truncated value"))
    }
    fn byte(&mut self) -> Result<u8> {
        let value = self.peek()?;
        self.offset += 1;
        Ok(value)
    }
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(Error::InvalidCbor("length overflow"))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(Error::InvalidCbor("truncated value"))?;
        self.offset = end;
        Ok(value)
    }
    fn head(&mut self) -> Result<(u8, u64)> {
        let first = self.byte()?;
        let major = first >> 5;
        let info = first & 31;
        let value = match info {
            0..=23 => info as u64,
            24 => {
                let v = self.byte()? as u64;
                if v < 24 {
                    return Err(Error::InvalidCbor("non-shortest integer or length"));
                }
                v
            }
            25 => {
                let raw = self.take(2)?;
                let v = u16::from_be_bytes(raw.try_into().unwrap()) as u64;
                if v <= 0xff {
                    return Err(Error::InvalidCbor("non-shortest integer or length"));
                }
                v
            }
            26 => {
                let raw = self.take(4)?;
                let v = u32::from_be_bytes(raw.try_into().unwrap()) as u64;
                if v <= 0xffff {
                    return Err(Error::InvalidCbor("non-shortest integer or length"));
                }
                v
            }
            27 => {
                let raw = self.take(8)?;
                let v = u64::from_be_bytes(raw.try_into().unwrap());
                if v <= 0xffff_ffff {
                    return Err(Error::InvalidCbor("non-shortest integer or length"));
                }
                v
            }
            _ => {
                return Err(Error::InvalidCbor(
                    "indefinite or reserved additional information",
                ))
            }
        };
        Ok((major, value))
    }
}
