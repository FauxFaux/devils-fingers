use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::net::Ipv4Addr;
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

pub fn dump_every<I>(_spec: &Spec, from: I) -> Result<(), Error>
where
    I: IntoIterator<Item = Result<Record, Error>>,
{
    for record in from {
        let record = record?;
        let data = record.data.as_ref();

        let flags = format!(
            "{}{}{}{}",
            if record.ack() { "A" } else { " " },
            if record.syn() { "S" } else { " " },
            if record.fin() { "F" } else { " " },
            if record.rst() { "R" } else { " " },
        );

        let prefix = format!(
            "{} n:{:02} ({:>22} -> {:22}) {} ",
            record.when,
            record.file_no,
            format!("{}", record.src),
            format!("{}", record.dest),
            flags
        );

        if data.is_empty() {
            println!("{} (no data)", prefix);
            continue;
        }

        match parse(data) {
            Ok(data) => println!("{} {:?}", prefix, data),
            Err(e) => {
                eprintln!(
                    "{} {:?} parsing {:?}",
                    prefix,
                    e,
                    String::from_utf8_lossy(data)
                );
            }
        }
    }

    Ok(())
}

pub fn naive_req_track<I>(spec: &Spec, from: I) -> Result<(), Error>
where
    I: IntoIterator<Item = Result<Record, Error>>,
{
    let mut last = HashMap::with_capacity(512);

    for record in from {
        let record = record?;
        let data = record.data.as_ref();

        if data.is_empty() {
            continue;
        }

        let data = match parse(data) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("{:?} parsing {:?}", e, String::from_utf8_lossy(data));
                continue;
            }
        };

        let tuple = match data {
            Recovered::Req(_) => (record.src, record.dest),
            Recovered::Resp(_) => (record.dest, record.src),
        };

        match data {
            Recovered::Req(req) => {
                if let Some(_original) = last.insert(tuple, (record.when, req.to_owned())) {
                    println!("duplicate req");
                }
            }
            Recovered::Resp(resp) => match last.remove(&tuple) {
                Some((start_time, req)) => {
                    display_transaction(spec, start_time, record.when, tuple.0, tuple.1, req, resp);
                }
                None => println!(
                    "{:?} {:?}: response with no request: {:?}",
                    record.when, tuple, resp
                ),
            },
        }
    }

    Ok(())
}

fn display_transaction(
    spec: &Spec,
    start: NaiveDateTime,
    end: NaiveDateTime,
    from: SocketAddrV4,
    to: SocketAddrV4,
    req: ReqO,
    resp: Resp,
) {
    let duration = end.signed_duration_since(start).num_milliseconds();
    let from = spec.name(from.ip());
    let to = spec.name(to.ip());
    let method = format!("{:?}", req.method).to_ascii_uppercase();
    println!(
        "{} {:22} {:22} {:>6} {:3} ({:5}ms) {:?}",
        start, from, to, method, resp.status, duration, req.path
    );
}

pub fn guess_names<I>(from: I) -> Result<HashMap<Ipv4Addr, String>, Error>
where
    I: IntoIterator<Item = Result<Record, Error>>,
{
    let psl = publicsuffix::List::from_reader(io::Cursor::new(
        &include_bytes!("../public_suffix_list.dat")[..],
    ))
    .expect("parsing static buffer");

    let mut hosts = HashMap::with_capacity(512);
    let mut uas = HashMap::with_capacity(512);

    for record in from {
        let record = record?;
        let mut data = record.data.as_ref();

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

        if let Recovered::Req(req) = data {
            if let Some(host) = req.host {
                hosts
                    .entry(record.dest.ip().to_owned())
                    .or_insert_with(|| HashSet::with_capacity(2))
                    .insert(host.to_string());
            }

            if let Some(ua) = req.ua {
                uas.entry(record.src.ip().to_owned())
                    .or_insert_with(|| HashSet::with_capacity(16))
                    .insert(ua.to_string());
            }
        }
    }

    println!("{:#?}", hosts);

    let mut pod_lookup = HashMap::with_capacity(hosts.len() / 2);

    for (addr, hosts) in &hosts {
        let nice: Vec<_> = hosts
            .iter()
            .filter(|host| {
                !(host.is_empty()
                    || "localhost" == *host
                    || host.starts_with("localhost:")
                    || public_domain(&psl, host)
                    || SocketAddrV4::from_str(host).is_ok()
                    || Ipv4Addr::from_str(host).is_ok())
            })
            .collect();

        match nice.len() {
            0 => println!("{}: no matches: {:?}", addr, hosts),
            1 => {
                pod_lookup.insert(
                    addr.to_owned(),
                    nice.into_iter().next().expect("length checked").to_string(),
                );
            }
            _ => println!("{}: m-m-m-multi matches: {:?}", addr, hosts),
        }
    }

    Ok(pod_lookup)
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
