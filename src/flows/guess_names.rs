use std::collections::HashMap;
use std::collections::HashSet;
use std::io;
use std::net::Ipv4Addr;
use std::net::SocketAddrV4;
use std::str::FromStr;

use anyhow::Error;
use cidr::Cidr as _;
use cidr::Ipv4Cidr;

use super::parse;
use super::public_domain;
use super::Recovered;
use crate::read::Record;
use crate::spec::Spec;

pub fn guess_names<I>(include: &Ipv4Cidr, from: I) -> Result<HashMap<Ipv4Addr, String>, Error>
where
    I: IntoIterator<Item = Result<Record, Error>>,
{
    let psl = publicsuffix::List::from_reader(io::Cursor::new(
        &include_bytes!("../../public_suffix_list.dat")[..],
    ))
    .expect("parsing static buffer");

    let mut hosts = HashMap::with_capacity(512);

    for record in from {
        let record = record?;

        if !include.contains(record.dest.ip()) {
            continue;
        }

        let data = match parse(record.data.as_ref()) {
            Ok(data) => data,
            Err(_) => continue,
        };

        if let Recovered::Req(req) = data {
            if let Some(mut host) = req.host {
                if let Some(colon) = host.find(':') {
                    host = &host[..colon];
                }
                let cluster_name = ".default.svc.cluster.local";
                if host.ends_with(cluster_name) {
                    host = &host[..host.len() - cluster_name.len()];
                }

                if clearly_not_pod_hostname(&psl, host) {
                    continue;
                }

                hosts
                    .entry(record.dest.ip().to_owned())
                    .or_insert_with(|| HashSet::with_capacity(2))
                    .insert(host.to_string());
            }
        }
    }

    let mut pod_lookup = HashMap::with_capacity(hosts.len() / 2);

    for (addr, hosts) in &hosts {
        match hosts.len() {
            0 => unreachable!(),
            1 => {
                pod_lookup.insert(
                    addr.to_owned(),
                    hosts
                        .into_iter()
                        .next()
                        .expect("length checked")
                        .to_string(),
                );
            }
            _ => println!("{}: m-m-m-multi matches: {:?}", addr, hosts),
        }
    }

    Ok(pod_lookup)
}

fn clearly_not_pod_hostname(psl: &publicsuffix::List, host: &str) -> bool {
    host.is_empty()
        || "localhost" == host
        || (host.contains('.') && public_domain(&psl, host))
        || Ipv4Addr::from_str(host).is_ok()
}
