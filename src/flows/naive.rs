use std::collections::HashMap;
use std::net::SocketAddrV4;

use chrono::NaiveDateTime;
use failure::Error;

use crate::read::Record;
use crate::spec::Spec;

use super::parse;
use super::Recovered;
use super::ReqO;
use super::Resp;

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
