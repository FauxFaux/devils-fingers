use std::collections::{HashMap, VecDeque};
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

        if !spec.first_node_spec().contains(src.ip()) {
            continue;
        }

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

                classify(seen)?;
                #[cfg(never)]
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

fn classify(seen: &Seen) -> Result<(), Error> {
    let mut packets = seen.packets.iter().collect::<VecDeque<_>>();

    let mut packet;
    loop {
        packet = packets.pop_front().ok_or_else(|| err_msg("no syn"))?;
        if packet.style.syn() {
            break;
        }
        log::debug!("discarding (pre-syn): {:?}", packet);
    }

    let syn = packet;

    loop {
        packet = packets
            .pop_front()
            .ok_or_else(|| err_msg("no syn follower"))?;
        if !packet.style.syn()
            || packet.when.signed_duration_since(syn.when) > Duration::milliseconds(100)
        {
            break;
        }
    }

    Ok(())
}
