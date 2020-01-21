use std::fmt;
use std::io;
use std::io::Read;

#[derive(Copy, Clone)]
pub struct Buffer {
    len: usize,
    inner: [u8; 512],
}

impl Buffer {
    pub fn empty() -> Buffer {
        Buffer {
            len: 0,
            inner: [0u8; 512],
        }
    }

    pub fn push_u8(&mut self, val: u8) {
        self.inner[self.len] = val;
        self.len += 1;
    }

    pub fn push_u16(&mut self, val: u16) {
        self.inner[self.len..self.len + 2].copy_from_slice(&val.to_le_bytes());
        self.len += 2;
    }

    pub fn push_u32(&mut self, val: u32) {
        self.inner[self.len..self.len + 4].copy_from_slice(&val.to_le_bytes());
        self.len += 4;
    }

    pub fn push_u64(&mut self, val: u64) {
        self.inner[self.len..self.len + 8].copy_from_slice(&val.to_le_bytes());
        self.len += 8;
    }

    pub fn extend_from_slice(&mut self, val: &[u8]) {
        self.inner[self.len..self.len + val.len()].copy_from_slice(val);
        self.len += val.len();
    }

    pub fn extend_from_reader<R: Read>(&mut self, mut reader: R, len: usize) -> io::Result<()> {
        reader.read_exact(&mut self.inner[self.len..self.len + len])?;
        self.len += len;
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn capacity(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        0 == self.len()
    }
}

impl AsRef<[u8]> for Buffer {
    fn as_ref(&self) -> &[u8] {
        &self.inner[..self.len]
    }
}

impl fmt::Debug for Buffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Buffer {{ len: {} }}", self.len)
    }
}
