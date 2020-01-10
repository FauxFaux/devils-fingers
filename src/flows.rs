use std::collections::VecDeque;
use std::convert::TryFrom;
use std::convert::TryInto;
use std::fs;
use std::io;
use std::io::Read;
use std::net::Ipv4Addr;
use std::str;
use std::str::FromStr;

use failure::bail;
use failure::err_msg;
use failure::format_err;
use failure::Error;
use failure::ResultExt;
use httparse::Header;
use httparse::Request;
use httparse::Response;

use crate::proto::Dec;
use crate::proto::Key;

pub fn flows(master: Key, files: Vec<&str>) -> Result<(), Error> {
    for file in files {
        process(master, fs::File::open(file)?)?;
    }
    Ok(())
}

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

fn process<R: Read>(master: Key, from: R) -> Result<(), Error> {
    let from = Dec::new(master, from)?;
    let from = Reader::new(from);
    let mut from = zstd::Decoder::new(from)?;
    loop {
        let mut record = [0u8; 256];
        from.read_exact(&mut record)?;

        let sec = i64::from_le_bytes(record[..8].try_into().expect("fixed slice"));
        let usec = i64::from_le_bytes(record[8..16].try_into().expect("fixed slice"));
        let src_ip: [u8; 4] = record[16..20].try_into().expect("fixed slice");
        let src_ip = Ipv4Addr::from(src_ip);
        let dst_ip: [u8; 4] = record[20..24].try_into().expect("fixed slice");
        let dst_ip = Ipv4Addr::from(dst_ip);
        let src_port = u16::from_le_bytes(record[24..26].try_into().expect("fixed slice"));
        let dst_port = u16::from_le_bytes(record[26..28].try_into().expect("fixed slice"));
        let mut data = &record[28..];

        // strip everything after the first null
        if let Some(i) = data.iter().position(|&c| c == 0) {
            data = &data[..i];
        }
        let data = match parse(data) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("{:?} parsing {:?}", e, String::from_utf8_lossy(data));
                continue;
            }
        };
    }

    Ok(())
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Method {
    Get,
    Post,
    Head,
    Put,
    Delete,
    Patch,
}

#[derive(Copy, Clone)]
enum Recovered<'s> {
    Req(Req<'s>),
    Resp(Resp<'s>),
}

#[derive(Copy, Clone)]
struct Req<'s> {
    method: Method,
    path: &'s str,
    host: Option<&'s str>,
    ua: Option<&'s str>,
}

#[derive(Copy, Clone)]
struct Resp<'s> {
    status: u16,
    content_type: Option<&'s str>,
    length: Option<u64>,
}

fn parse(data: &[u8]) -> Result<Recovered, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    if data.starts_with(b"HTTP") {
        let mut resp = Response::new(&mut headers);
        let complete = resp.parse(data)?.is_complete();
        let status = resp.code.ok_or_else(|| err_msg("no code?"))?;
        Ok(Recovered::Resp(Resp {
            status,
            content_type: find_header("content-type", &headers),
            length: find_header("content-length", &headers).and_then(|v| u64::from_str(v).ok()),
        }))
    } else {
        let mut req = Request::new(&mut headers);
        let complete = req.parse(data)?.is_complete();
        let method = match req.method {
            Some("GET") => Method::Get,
            Some("POST") => Method::Post,
            Some("HEAD") => Method::Head,
            Some("PUT") => Method::Put,
            Some("DELETE") => Method::Delete,
            Some("PATCH") => Method::Patch,
            other => return Err(format_err!("bad method: {:?}", other)),
        };
        match req.path {
            Some(path) => Ok(Recovered::Req(Req {
                method,
                path,
                host: find_header("host", &headers),
                ua: find_header("user-agent", &headers),
            })),
            None => match data.iter().position(|&c| c == b'\n') {
                Some(_) => bail!("no path but header line is complete?"),
                None => match data.iter().position(|&c| c == b' ') {
                    Some(sep) => Ok(Recovered::Req(Req {
                        method,
                        path: str::from_utf8(&data[sep..])?,
                        host: None,
                        ua: None,
                    })),
                    None => bail!("header line with no space?!"),
                },
            },
        }
    }
}

fn find_header<'h>(key: &str, headers: &[Header<'h>]) -> Option<&'h str> {
    for header in headers {
        if header.name.eq_ignore_ascii_case(key) {
            return str::from_utf8(header.value).ok();
        }
    }
    None
}

#[test]
fn vec_deck_slices() {
    let mut buf = VecDeque::new();
    buf.push_back(1usize);
    assert_eq!((&[1][..], &[][..]), buf.as_slices());
    buf.push_front(2usize);
    assert_eq!((&[2][..], &[1][..]), buf.as_slices());
    buf.pop_front().unwrap();
    assert_eq!((&[1][..], &[][..]), buf.as_slices());
}
