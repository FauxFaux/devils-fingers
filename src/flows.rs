use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::io::Read;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::str;
use std::str::FromStr;

use failure::bail;
use failure::err_msg;
use failure::format_err;
use failure::Error;
use httparse::Header;
use httparse::Request;
use httparse::Response;

use crate::read;
use crate::spec::Spec;
use chrono::NaiveDateTime;

pub fn flows(spec: Spec, files: Vec<&str>) -> Result<(), Error> {
    for file in files {
        process(&spec, fs::File::open(file)?)?;
    }
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct Stats {
    records: u64,
    duplicates_after_time: u64,
    parse_error: u64,
    rogue_req: u64,
    rogue_resp: u64,
}

fn process<R: Read>(spec: &Spec, from: R) -> Result<(), Error> {
    let mut last = HashMap::with_capacity(512);

    let mut stats = Stats::default();

    read::read_frames(from, |record| {
        let mut data = record.data;

        // strip everything after the first null
        if let Some(i) = data.iter().position(|&c| c == 0) {
            data = &data[..i];
        }
        let data = match parse(data) {
            Ok(data) => data,
            Err(e) => {
                stats.parse_error += 1;
                eprintln!("{:?} parsing {:?}", e, String::from_utf8_lossy(data));
                return Ok(());
            }
        };

        let time = record.when;

        let tuple = match data {
            Recovered::Req(_) => (record.src, record.dest),
            Recovered::Resp(_) => (record.dest, record.src),
        };

        match data {
            Recovered::Req(req) => {
                if let Some(_original) = last.insert(tuple, (time, req.to_owned())) {
                    stats.rogue_req += 1;
                    println!("duplicate req");
                }
            }
            Recovered::Resp(resp) => match last.remove(&tuple) {
                Some((start_time, req)) => {
                    display_transaction(spec, start_time, time, tuple.0, tuple.1, req, resp);
                }
                None => {
                    stats.rogue_resp += 1;
                    println!(
                        "{:?} {:?}: response with no request: {:?}",
                        record.when, tuple, resp
                    )
                }
            },
        }
        Ok(())
    })?;

    println!("{:#?}", stats);

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

fn guess_names<R: Read>(from: R) -> Result<HashMap<Ipv4Addr, String>, Error> {
    let psl = publicsuffix::List::from_reader(io::Cursor::new(
        &include_bytes!("../public_suffix_list.dat")[..],
    ))
    .expect("parsing static buffer");

    let mut hosts = HashMap::with_capacity(512);
    let mut uas = HashMap::with_capacity(512);

    read::read_frames(from, |record| {
        let mut data = record.data;

        // strip everything after the first null
        if let Some(i) = data.iter().position(|&c| c == 0) {
            data = &data[..i];
        }
        let data = match parse(data) {
            Ok(data) => data,
            Err(e) => {
                eprintln!("{:?} parsing {:?}", e, String::from_utf8_lossy(data));
                return Ok(());
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

        Ok(())
    })?;

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
