use std::collections::VecDeque;
use std::collections::{HashMap, HashSet};
use std::iter::Peekable;
use std::net::SocketAddrV4;

use chrono::Duration;
use chrono::NaiveDateTime;
use cidr::Cidr as _;
use failure::bail;
use failure::err_msg;
use failure::Error;
use itertools::Itertools;

use crate::read::Record;
use crate::spec::Spec;

use super::parse;
use super::Recovered;
use super::ReqO;
use super::Resp;

#[derive(Clone, Debug)]
struct Seen {
    packets: Vec<Packet>,
    latest: NaiveDateTime,
}

#[derive(Clone, Debug)]
struct Packet {
    when: NaiveDateTime,
    other: SocketAddrV4,
    style: PacketType,
}

#[derive(Clone, Debug)]
enum PacketType {
    Syn,
    SynAck,
    Req(ReqO),
    Resp(Resp),
    ShutdownSent(u8),
    ShutdownRecv(u8),
}

impl PacketType {
    fn syn(&self) -> bool {
        match self {
            PacketType::Syn => true,
            _ => false,
        }
    }

    fn syn_ack(&self) -> bool {
        match self {
            PacketType::SynAck => true,
            _ => false,
        }
    }

    fn req(&self) -> Option<&ReqO> {
        match self {
            PacketType::Req(req) => Some(req),
            _ => None,
        }
    }

    fn resp(&self) -> Option<&Resp> {
        match self {
            PacketType::Resp(resp) => Some(resp),
            _ => None,
        }
    }

    fn shutdown(&self) -> bool {
        match self {
            PacketType::ShutdownSent(_) | PacketType::ShutdownRecv(_) => true,
            _ => false,
        }
    }
}

impl Seen {
    fn accept(&mut self, packet: Packet) {
        self.latest = packet.when;
        self.packets.push(packet);
    }

    fn shutdown_packets(&self) -> impl Iterator<Item = &Packet> {
        self.packets.iter().filter(|p| p.style.shutdown())
    }

    fn finished_before(&self, now: &NaiveDateTime) -> bool {
        let shutdowns = self.shutdown_packets().collect_vec();
        !shutdowns.is_empty() && shutdowns.into_iter().all(|p| p.when < *now)
    }
}

pub fn by_source<I>(spec: &Spec, from: I) -> Result<(), Error>
where
    I: IntoIterator<Item = Result<Record, Error>>,
{
    let mut last = HashMap::with_capacity(512);

    for (i, record) in from.into_iter().enumerate() {
        let record: Record = record?;

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

        let seen = last.entry(src).or_insert_with(|| Seen {
            packets: Vec::with_capacity(16),
            latest: NaiveDateTime::from_timestamp(0, 0),
        });

        let style = if record.syn() && record.ack() {
            PacketType::SynAck
        } else if record.syn() {
            PacketType::Syn
        } else if record.fin() || record.rst() {
            if outbound {
                PacketType::ShutdownSent(record.flags)
            } else {
                PacketType::ShutdownRecv(record.flags)
            }
        } else {
            match parse(record.data.as_ref()) {
                Ok(Recovered::Req(req)) => PacketType::Req(req.to_owned()),
                Ok(Recovered::Resp(resp)) => PacketType::Resp(resp),
                Err(_) => continue,
            }
        };

        let packet = Packet {
            when: record.when,
            other: if outbound { record.dest } else { record.src },
            style,
        };

        seen.accept(packet);

        // occasionally
        if i % 1_000 == 0 {
            let mut the_past: NaiveDateTime = record.when;
            the_past -= Duration::seconds(1);
            let mut done = Vec::new();
            for (key, seen) in &last {
                if !seen.finished_before(&the_past) {
                    continue;
                }

                let connection = deconstruct(seen)?;
                if bored_of(spec, key, connection)? {
                    done.push(*key);
                }
            }

            println!(
                "{}: {}/{} can be removed",
                record.when,
                done.len(),
                last.len()
            );

            for key in done {
                last.remove(&key);
            }
        }
    }

    unimplemented!()
}

struct Connection<'p> {
    prefix: Vec<&'p Packet>,
    syns: Vec<&'p Packet>,
    syn_acks: Vec<&'p Packet>,
    http: Vec<(Vec<&'p Packet>, Vec<&'p Packet>)>,
    shutdowns: Vec<&'p Packet>,
    suffix: Vec<&'p Packet>,
}

fn bored_of(spec: &Spec, key: &SocketAddrV4, conn: Connection) -> Result<bool, Error> {
    if conn.http.is_empty() {
        return Ok(false);
    }

    for (reqs, resps) in conn.http {
        let mut request = HashSet::with_capacity(4);
        let mut times = Vec::with_capacity(reqs.len() + resps.len());
        for req in reqs {
            times.push(req.when);
            match &req.style {
                PacketType::Req(req) => {
                    request.insert((req.method, req.path.as_str()));
                }
                _ => unreachable!(),
            }
        }

        let mut response = HashSet::with_capacity(4);

        for resp in &resps {
            times.push(resp.when);
            match &resp.style {
                PacketType::Resp(resp) => {
                    response.insert((resp.status, resp.length));
                }
                _ => unreachable!(),
            }
        }
        let start = times.iter().min().expect("non-empty");

        if request.len() != 1 || response.len() != 1 {
            eprintln!("{} {:22} BAD BAD BAD BAD: {:?} {:?}", start, key, request, response);
            return Ok(true);
        }

        let (method, path) = request.into_iter().next().expect("len above");
        let (status, length) = response.into_iter().next().expect("len above");

        let end = times.iter().max().expect("non-empty");
        let duration = end.signed_duration_since(*start).num_milliseconds();

        let method = format!("{:?}", method).to_ascii_uppercase();

        let from = spec.name(key.ip());
        let to = spec.name(&resps[0].other.ip());

        let length = match length {
            Some(v) => format!("{}", v),
            None => format!("?"),
        };

        println!(
            "{} {:22} {:22} {:>6} {:3} ({:5}ms) {:>5} {}",
            start, from, to, method, status, duration, length, path
        );
    }

    Ok(true)
}

fn deconstruct(seen: &Seen) -> Result<Connection, Error> {
    let mut packets = seen.packets.iter().peekable();

    let prefix = drop_until(&mut packets, |p| p.style.syn());

    let syns = take_while(&mut packets, |p| p.style.syn());
    let syn_acks = take_while(&mut packets, |p| p.style.syn_ack());

    let mut http = Vec::with_capacity(2);
    loop {
        let reqs = take_while(&mut packets, |p| p.style.req().is_some());
        let resps = take_while(&mut packets, |p| p.style.resp().is_some());

        if !reqs.is_empty() || !resps.is_empty() {
            http.push((reqs, resps));
        } else {
            break;
        }
    }

    let shutdowns = take_while(&mut packets, |p| p.style.shutdown());
    let suffix = packets.collect();

    Ok(Connection {
        prefix,
        syns,
        syn_acks,
        http,
        shutdowns,
        suffix,
    })
}

#[inline]
fn drop_until<P, I, C>(iter: &mut Peekable<I>, mut condition: C) -> Vec<P>
where
    I: Iterator<Item = P>,
    C: FnMut(&P) -> bool,
{
    take_while(iter, |c| !condition(c))
}

fn take_while<P, I, C>(iter: &mut Peekable<I>, mut condition: C) -> Vec<P>
where
    I: Iterator<Item = P>,
    C: FnMut(&P) -> bool,
{
    let mut ret = Vec::with_capacity(4);
    while match iter.peek() {
        Some(v) if condition(v) => true,
        Some(_) => false,
        None => false,
    } {
        ret.push(iter.next().expect("peeked"));
    }
    ret
}

#[test]
fn combinators() {
    let mut numbers = vec![1, 2, 3, 4, 5].into_iter().peekable();
    assert_eq!(vec![1, 2], take_while(&mut numbers, |&v| v < 3));
    assert_eq!(vec![3, 4, 5], numbers.collect_vec());

    let mut numbers = vec![1, 2, 3, 4, 5].into_iter().peekable();
    assert_eq!(vec![1, 2], drop_until(&mut numbers, |&v| v == 3));
    assert_eq!(vec![3, 4, 5], numbers.collect_vec());
}
