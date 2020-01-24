use std::collections::HashMap;
use std::net::SocketAddrV4;

use chrono::Duration;
use chrono::NaiveDateTime;
use cidr::Cidr as _;
use failure::Error;

use crate::read::Record;
use crate::spec::Spec;

use super::parse;
use super::Recovered;
use super::ReqO;
use super::Resp;

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
        } else if record.fin() || record.rst() {
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
        if i % 1_000 == 0 {
            let mut the_past: NaiveDateTime = record.when;
            the_past -= Duration::seconds(1);
            let mut done = Vec::new();
            for (key, seen) in &last {
                if !seen.finished_before(&the_past) {
                    continue;
                }

                match classify(seen)? {
                    Classification::HopingForMore => continue,
                    Classification::OrderingConcern => {
                        println!("{:?} ordering concern: {:#?}", key, seen)
                    }
                    Classification::OpenFor(d) => println!(
                        "{:6} {:?} {:?} open for {}",
                        last.len(),
                        key,
                        seen.syn[0],
                        d
                    ),
                    Classification::Unknown => (),
                }

                done.push(*key);
            }

            for key in done {
                last.remove(&key);
            }
        }
    }

    unimplemented!()
}

enum Classification {
    Unknown,
    HopingForMore,
    OrderingConcern,
    OpenFor(Duration),
}

fn classify(seen: &Seen) -> Result<Classification, Error> {
    let (last_syn, first_syn_ack, last_syn_ack, first_fin) = match ordering_dates(seen) {
        Some(dates) => dates,
        None => return Ok(Classification::HopingForMore),
    };

    let resp = first_syn_ack.signed_duration_since(last_syn);
    if resp < Duration::zero() || resp > Duration::milliseconds(100) {
        return Ok(Classification::OrderingConcern);
    }

    let resp = first_fin.signed_duration_since(last_syn_ack);
    if resp < Duration::zero() || resp > Duration::minutes(20) {
        return Ok(Classification::OrderingConcern);
    }

    Ok(Classification::OpenFor(
        first_fin.signed_duration_since(last_syn),
    ))
}

fn ordering_dates(
    seen: &Seen,
) -> Option<(NaiveDateTime, NaiveDateTime, NaiveDateTime, NaiveDateTime)> {
    let last_syn = seen.syn.iter().map(|(when, ..)| when).copied().max()?;
    let first_syn_ack = seen.syn_ack.iter().map(|(when, ..)| when).copied().min()?;
    let last_syn_ack = seen.syn_ack.iter().map(|(when, ..)| when).copied().max()?;
    let first_fin = seen.fin.iter().map(|(when, ..)| when).copied().min()?;

    Some((last_syn, first_syn_ack, last_syn_ack, first_fin))
}
