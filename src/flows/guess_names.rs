use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::str::FromStr;

use failure::Error;

use crate::read::Record;

use super::parse;
use super::public_domain;
use super::Recovered;

pub fn guess_names<I>(from: I) -> Result<HashMap<Ipv4Addr, String>, Error>
where
    I: IntoIterator<Item = Result<Record, Error>>,
{
    let psl = publicsuffix::List::from_reader(io::Cursor::new(
        &include_bytes!("../../public_suffix_list.dat")[..],
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
