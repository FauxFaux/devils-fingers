use std::collections::VecDeque;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::io;
use std::io::Read;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use chrono::NaiveDateTime;
use failure::Error;

use crate::proto::Dec;
use crate::proto::Key;

struct Reader<R> {
    dec: Dec<R>,
    buf: VecDeque<u8>,
}

impl<R> Reader<R> {
    fn new(dec: Dec<R>) -> Self {
        Reader {
            dec,
            buf: VecDeque::with_capacity(8 * 1024),
        }
    }
}

impl<R: Read> Read for Reader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        while self.buf.is_empty() {
            match self.dec.read_frame()? {
                Some(buf) => self.buf.extend(buf),
                None => return Ok(0),
            }
        }

        let (from, _) = self.buf.as_slices();
        assert!(!from.is_empty());

        let reading = buf.len().min(from.len());
        buf[..reading].copy_from_slice(&from[..reading]);
        self.buf.drain(..reading);
        Ok(reading)
    }
}

pub struct Record<'b> {
    pub when: NaiveDateTime,
    pub src: SocketAddrV4,
    pub dest: SocketAddrV4,
    pub data: &'b [u8],
}

pub fn read_frames<R: Read, F>(master: Key, from: R, mut into: F) -> Result<(), Error>
where
    F: FnMut(Record<'_>) -> Result<(), Error>,
{
    let from = Dec::new(master, from)?;
    let from = Reader::new(from);
    let mut from = zstd::Decoder::new(from)?;
    let mut previous: Option<[u8; 512]> = None;

    loop {
        let mut record = [0u8; 512];
        if let Err(e) = from.read_exact(&mut record) {
            eprintln!("input error: {:?}", e);
            break;
        }

        // if the last record we processed was equal to this one, excluding the timestamp, skip it
        // we see these duplicates a lot. I'm suspecting some kind of routing shenanigans, we
        // observe it as it passes out of a container to the host, then again as it passes back in?
        // I have no proof of this claim. I'm yet to see any that aren't adjacent.
        // Guess is based mostly on the two-digit-nano times between the packet hops, and the
        // ordering/clustering; e.g. three in, then three out.
        if let Some(previous) = previous {
            if record[16..] == previous[16..] {
                continue;
            }
        }

        previous = Some(record);

        let when = {
            let usec = u64::from_le_bytes(record[..8].try_into().expect("fixed slice"));
            let sec = i64::try_from(usec / 1_000_000)?;
            let usec = u32::try_from(usec % 1_000_000)?;
            NaiveDateTime::from_timestamp(sec, usec * 1000)
        };

        let src = read_addr(&record[8..14]);
        let dest = read_addr(&record[14..20]);

        let data = &record[20..];

        into(Record {
            when,
            src,
            dest,
            data,
        })?;
    }

    Ok(())
}

fn read_addr(data: &[u8]) -> SocketAddrV4 {
    assert_eq!(6, data.len());
    SocketAddrV4::new(
        Ipv4Addr::new(data[0], data[1], data[2], data[3]),
        u16::from_le_bytes(data[4..6].try_into().expect("fixed slice")),
    )
}
