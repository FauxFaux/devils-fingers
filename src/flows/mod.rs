use std::collections::HashMap;
use std::fs;
use std::net::SocketAddrV4;
use std::str;
use std::str::FromStr;

use chrono::Duration;
use chrono::NaiveDateTime;
use cidr::Cidr as _;
use failure::bail;
use failure::err_msg;
use failure::format_err;
use failure::Error;
use httparse::Header;
use httparse::Request;
use httparse::Response;
use itertools::Itertools;

use crate::read::ReadFrames;
use crate::read::Record;
use crate::spec::Spec;

mod guess_names;
mod naive;

pub use guess_names::guess_names;
pub use naive::dump_every;
pub use naive::naive_req_track;

pub fn all_files(files: &[&str]) -> Result<impl Iterator<Item = Result<Record, Error>>, Error> {
    let mut sources = Vec::with_capacity(files.len());
    for (file_no, file) in files.into_iter().enumerate() {
        let file = fs::File::open(file)?;
        let file = zstd::Decoder::new(file)?;
        sources.push(ReadFrames::new(file, file_no));
    }

    Ok(sources.into_iter().kmerge_by(|left, right| {
        left.as_ref().ok().map(|v| v.when) < right.as_ref().ok().map(|v| v.when)
    }))
}

#[derive(Clone, Debug, Default)]
struct Stats {
    records: u64,
    duplicates_after_time: u64,
    parse_error: u64,
    rogue_req: u64,
    rogue_resp: u64,
}

#[derive(Clone, Debug, Default)]
struct Seen {
    syn: Vec<(NaiveDateTime, SocketAddrV4)>,
    syn_ack: Vec<(NaiveDateTime, SocketAddrV4)>,
    req: Vec<(NaiveDateTime, SocketAddrV4, ReqO)>,
    res: Vec<(NaiveDateTime, SocketAddrV4, Resp)>,
    fin: Vec<(NaiveDateTime, (SocketAddrV4, SocketAddrV4), u8)>,
}

impl Seen {
    fn finished_before(&self, now: &NaiveDateTime) -> bool {
        !self.fin.is_empty() && self.fin.iter().all(|(when, ..)| when < now)
    }
}

pub fn by_source<I>(spec: &Spec, from: I) -> Result<(), Error>
where
    I: IntoIterator<Item = Result<Record, Error>>,
{
    let mut last = HashMap::with_capacity(512);

    for (i, record) in from.into_iter().enumerate() {
        let record = record?;

        let outbound = if record.syn() && record.ack() {
            Some(false)
        } else if record.syn() {
            Some(true)
        } else if record.data.is_empty() {
            // probably a fin or something, but I've decided these are non-directional
            None
        } else {
            match parse(record.data.as_ref()) {
                Ok(Recovered::Req(_)) => Some(true),
                Ok(Recovered::Resp(_)) => Some(false),
                Err(_) => None,
            }
        };

        let outbound = match outbound {
            Some(v) => v,
            None => {
                let has_src = last.contains_key(&record.src);
                let has_dst = last.contains_key(&record.dest);

                if has_src != has_dst {
                    has_src
                } else {
                    // really getting pretty yolo at this point
                    record.src.port() > record.dest.port()
                }
            }
        };

        let src = if outbound { record.src } else { record.dest };

        if !spec.first_node_spec().contains(src.ip()) {
            continue;
        }

        let seen = last.entry(src).or_insert_with(|| Seen::default());

        if record.syn() && record.ack() {
            seen.syn_ack.push((record.when, record.dest));
        } else if record.syn() {
            seen.syn.push((record.when, record.src));
        } else if record.fin() {
            seen.fin
                .push((record.when, (record.src, record.dest), record.flags));
        } else {
            match parse(record.data.as_ref()) {
                Ok(Recovered::Req(req)) => {
                    seen.req.push((record.when, record.dest, req.to_owned()))
                }
                Ok(Recovered::Resp(resp)) => seen.res.push((record.when, record.src, resp)),
                Err(_) => (),
            }
        };

        // occasionally
        if i % 10_000 == 0 {
            let mut the_past: NaiveDateTime = record.when;
            the_past -= Duration::seconds(1);
            let mut done = Vec::new();
            for (key, seen) in &last {
                if !seen.finished_before(&the_past) {
                    continue;
                }

                println!("{:#?}", seen);

                done.push(*key);
            }

            for key in done {
                last.remove(&key);
            }
        }
    }

    unimplemented!()
}

fn public_domain(psl: &publicsuffix::List, domain: &str) -> bool {
    if let Ok(domain) = psl.parse_dns_name(domain) {
        if let Some(domain) = domain.domain() {
            domain.has_known_suffix()
        } else {
            false
        }
    } else {
        false
    }
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

#[derive(Clone, Debug)]
enum Recovered<'s> {
    Req(Req<'s>),
    Resp(Resp),
}

#[derive(Copy, Clone, Debug)]
struct Req<'s> {
    method: Method,
    path: &'s str,
    host: Option<&'s str>,
    ua: Option<&'s str>,
}

#[derive(Clone, Debug)]
struct ReqO {
    method: Method,
    path: String,
    host: Option<String>,
    ua: Option<String>,
}

impl Req<'_> {
    fn to_owned(&self) -> ReqO {
        ReqO {
            method: self.method,
            path: self.path.to_owned(),
            host: self.host.map(|v| v.to_owned()),
            ua: self.ua.map(|v| v.to_owned()),
        }
    }
}

#[derive(Clone, Debug)]
struct Resp {
    status: u16,
    content_type: Option<String>,
    length: Option<u64>,
}

fn parse(data: &[u8]) -> Result<Recovered, Error> {
    let mut headers = [httparse::EMPTY_HEADER; 32];
    if data.starts_with(b"HTTP") {
        let mut resp = Response::new(&mut headers);
        let _complete = resp.parse(data)?.is_complete();
        let status = resp.code.ok_or_else(|| err_msg("no code?"))?;
        Ok(Recovered::Resp(Resp {
            status,
            content_type: find_header("content-type", &headers).map(|v| v.to_string()),
            length: find_header("content-length", &headers).and_then(|v| u64::from_str(v).ok()),
        }))
    } else {
        let mut req = Request::new(&mut headers);
        req.parse(data)?;
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
fn merge() {
    assert_eq!(
        itertools::kmerge(vec![vec![3, 6, 9], vec![1, 4, 7], vec![2, 6, 6, 8]]).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 6, 6, 6, 7, 8, 9]
    );
}
