use std::convert::TryFrom;
use std::io;
use std::io::Read;
use std::io::Write;

use aead::Aead as _;
use aead::NewAead as _;
use aead::Payload;
use chacha20poly1305::XChaCha20Poly1305 as Cha;
use failure::ensure;
use failure::Error;
use generic_array::GenericArray;

pub type Key = [u8; 32];

const MAGIC: [u8; 8] = *b"pcapdump";

pub struct Enc<W> {
    inner: W,
    ctr: u64,
    nonce_base: [u8; 16],
    cipher: Cha,
}

impl<W: Write> Enc<W> {
    pub fn new(master: Key, mut inner: W) -> Result<Self, Error> {
        inner.write_all(&MAGIC)?;
        let nonce_base: [u8; 16] = rand::random();
        inner.write_all(&nonce_base)?;
        Ok(Enc {
            inner,
            ctr: 0,
            cipher: Cha::new(master.into()),
            nonce_base,
        })
    }
}

impl<W: Write> Write for Enc<W> {
    fn write(&mut self, data: &[u8]) -> Result<usize, io::Error> {
        if data.is_empty() {
            return Ok(0);
        }

        let data = &data[..data.len().min(65000)];
        let len = u16::try_from(data.len()).expect("clamped to 65k");

        let nonce = build_nonce(&self.nonce_base, self.ctr);

        self.ctr += 1;

        let len_bytes = len.to_le_bytes();

        let ciphertext = self
            .cipher
            .encrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: &data,
                    aad: &len_bytes,
                },
            )
            .expect("static sizes");

        self.inner.write_all(&len_bytes)?;
        self.inner.write_all(&ciphertext)?;

        Ok(data.len())
    }

    fn flush(&mut self) -> Result<(), io::Error> {
        self.inner.flush()
    }
}

fn build_nonce(nonce_base: &[u8; 16], ctr: u64) -> [u8; 24] {
    let mut nonce = [0u8; 24];
    nonce[..16].copy_from_slice(nonce_base);
    nonce[16..].copy_from_slice(&ctr.to_le_bytes());
    nonce
}

pub struct Dec<R> {
    inner: R,
    ctr: u64,
    nonce_base: [u8; 16],
    cipher: Cha,
}

impl<R: Read> Dec<R> {
    pub fn new(master: Key, mut inner: R) -> Result<Self, Error> {
        let mut eight = [0u8; 8];
        inner.read_exact(&mut eight)?;
        ensure!(eight == MAGIC, "invalid magic");
        let mut nonce_base = [0u8; 16];
        inner.read_exact(&mut nonce_base)?;
        Ok(Dec {
            inner,
            ctr: 0,
            cipher: Cha::new(master.into()),
            nonce_base,
        })
    }

    pub fn read_frame(&mut self) -> Result<Option<Vec<u8>>, io::Error> {
        let mut len_bytes = [0u8; 2];
        self.inner.read_exact(&mut len_bytes)?;
        let len = usize::from(u16::from_le_bytes(len_bytes));

        let mut data = vec![0u8; len + 16];
        match self.inner.read_exact(&mut data) {
            Ok(()) => (),
            Err(ref e) if io::ErrorKind::UnexpectedEof == e.kind() => return Ok(None),
            Err(e) => return Err(e),
        };

        let nonce = build_nonce(&self.nonce_base, self.ctr);
        self.ctr += 1;

        match self.cipher.decrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: &data,
                aad: &len_bytes,
            },
        ) {
            Ok(buf) => Ok(Some(buf)),
            Err(_) => Err(io::ErrorKind::InvalidData.into()),
        }
    }
}

#[test]
fn round_trip() -> Result<(), Error> {
    let master = rand::random();
    let mut buf = Vec::new();
    let mut enc = Enc::new(master, &mut buf)?;
    enc.write_all(b"hai")?;
    assert_eq!(buf.len(), 8 + 16 + 2 + 3 + 16);
    let mut dec = Dec::new(master, io::Cursor::new(buf))?;
    assert_eq!(b"hai", dec.read_frame()?.expect("frame").as_slice());
    Ok(())
}
