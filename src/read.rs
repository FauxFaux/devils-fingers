use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::Read;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use anyhow::ensure;
use anyhow::Error;
use chrono::NaiveDateTime;
use insideout::InsideOut as _;

use crate::buffer::Buffer;

#[derive(Copy, Clone, Debug)]
pub struct Record {
    pub file_no: usize,
    pub when: NaiveDateTime,
    pub src: SocketAddrV4,
    pub dest: SocketAddrV4,
    pub flags: u8,
    pub data: Buffer,
}

impl Record {
    pub fn fin(&self) -> bool {
        0 != (self.flags & 1)
    }
    pub fn syn(&self) -> bool {
        0 != (self.flags & 2)
    }

    pub fn rst(&self) -> bool {
        0 != (self.flags & 4)
    }

    pub fn ack(&self) -> bool {
        0 != (self.flags & 16)
    }
}

pub struct ReadFrames<R, M> {
    from: R,
    meta: M,
}

impl<R, M> ReadFrames<R, M> {
    pub fn new(from: R, meta: M) -> Self {
        ReadFrames { from, meta }
    }
}

impl<R: Read> Iterator for ReadFrames<R, usize> {
    type Item = Result<Record, Error>;

    fn next(&mut self) -> Option<Self::Item> {
        read_frame(&mut self.from, self.meta).inside_out()
    }
}

fn read_frame<R: Read>(mut from: R, file_no: usize) -> Result<Option<Record>, Error> {
    const HEADER_LEN: usize = 21;

    let mut header = [0u8; 2 + HEADER_LEN];
    if let Err(e) = from.read_exact(&mut header) {
        eprintln!("input error: {:?}", e);
        return Ok(None);
    }

    let mut data = Buffer::empty();

    let len = u16::from_le_bytes(header[..2].try_into()?);
    ensure!(
        len >= u16::try_from(HEADER_LEN).expect("constant"),
        "data len including header but excluding length is too short: {}",
        len
    );

    let data_len = usize::from(len) - HEADER_LEN;

    ensure!(
        data_len < data.capacity(),
        "data len including header but excluding length is too short"
    );

    let record = &header[2..];

    let when = {
        let usec = u64::from_le_bytes(record[..8].try_into().expect("fixed slice"));
        let sec = i64::try_from(usec / 1_000_000)?;
        let usec = u32::try_from(usec % 1_000_000)?;
        NaiveDateTime::from_timestamp(sec, usec * 1000)
    };

    let src = read_addr(&record[8..14]);
    let dest = read_addr(&record[14..20]);

    let flags = record[20];

    data.extend_from_reader(from, data_len)?;

    Ok(Some(Record {
        file_no,
        when,
        src,
        dest,
        flags,
        data,
    }))
}

fn read_addr(data: &[u8]) -> SocketAddrV4 {
    assert_eq!(6, data.len());
    SocketAddrV4::new(
        Ipv4Addr::new(data[0], data[1], data[2], data[3]),
        u16::from_le_bytes(data[4..6].try_into().expect("fixed slice")),
    )
}
