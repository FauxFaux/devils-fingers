use std::convert::TryFrom;
use std::convert::TryInto;
use std::io::Read;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;

use chrono::NaiveDateTime;
use failure::Error;

pub struct Record<'b> {
    pub when: NaiveDateTime,
    pub src: SocketAddrV4,
    pub dest: SocketAddrV4,
    pub data: &'b [u8],
}

pub fn read_frames<R: Read, F>(from: R, mut into: F) -> Result<(), Error>
where
    F: FnMut(Record<'_>) -> Result<(), Error>,
{
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
