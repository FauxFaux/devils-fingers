use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::io;
use std::io::BufRead;
use std::io::Read;
use std::net::Ipv4Addr;
use std::str::FromStr;

use chrono::{DateTime, NaiveDateTime};
use cidr::Cidr;
use cidr::Ipv4Cidr;
use failure::format_err;
use failure::Error;
use failure::ResultExt;
use serde::Deserialize;
use serde::Deserializer;
use serde_derive::Deserialize;
use serde_json::Value;

type Date = chrono::DateTime<chrono::Utc>;

pub type Spec = Lookup;

pub fn load<R: Read>(rdr: R) -> Result<Vec<Lookup>, Error> {
    let mut lookups = Vec::with_capacity(32);
    for (no, line) in io::BufReader::new(rdr).lines().enumerate() {
        let line = line?;
        let whole: Together =
            serde_json::from_str(&line).with_context(|_| format_err!("loading line {}", no))?;
        lookups.push(whole.into_lookup());
    }

    Ok(lookups)
}

#[derive(Debug)]
pub struct Lookup {
    when: Date,
    descriptions: HashMap<Ipv4Addr, Description>,
}

impl Lookup {
    pub fn name(&self, addr: &Ipv4Addr) -> String {
        if let Some(stored) = self.descriptions.get(addr) {
            stored.to_string()
        } else {
            format!("{}", addr)
        }
    }
}

#[derive(Debug)]
enum Description {
    ServiceClusterIp(String),
    Pod(String),
}

impl fmt::Display for Description {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Description::ServiceClusterIp(name) => write!(f, "svc:{}", name),
            Description::Pod(name) => write!(f, "{}", name),
        }
    }
}

impl Together {
    fn pod_label(&self, pod: &Item<PodSpec, PodStatus>) -> Option<String> {
        if let Some(labels) = pod.metadata.labels.as_ref() {
            if let Some(name) = labels.get("name") {
                return Some(name.to_string());
            }
        }

        if let Some(container) = pod.spec.containers.get(0) {
            return Some(container.name.to_string());
        }

        None
    }

    fn into_lookup(self) -> Lookup {
        let mut descriptions = HashMap::with_capacity(self.po.items.len() + self.svc.items.len());

        for pod in &self.po.items {
            if let Some(label) = self.pod_label(pod) {
                if let Some(pod_ip) = pod.status.pod_ip.clone() {
                    descriptions.insert(pod_ip, Description::Pod(label));
                }
            }
        }

        for service in &self.svc.items {
            if let ServiceSpec::ClusterIp { cluster_ip, .. } = &service.spec {
                if let Ok(cluster_ip) = Ipv4Addr::from_str(cluster_ip) {
                    let label = service.metadata.name.to_string();
                    descriptions.insert(cluster_ip, Description::ServiceClusterIp(label));
                }
            }
        }

        Lookup {
            when: self.now,
            descriptions,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct Nah {}

#[derive(Clone, Debug, Deserialize)]
pub struct Together {
    now: Date,
    po: ListDoc<PodSpec, PodStatus>,
    no: ListDoc<NodeSpec, NodeStatus>,
    svc: ListDoc<ServiceSpec, Nah>,
}

#[derive(Clone, Debug, Deserialize)]
struct ListDoc<S, T> {
    items: Vec<Item<S, T>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Metadata {
    creation_timestamp: Date,
    labels: Option<HashMap<String, String>>,
    name: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Item<S, T> {
    metadata: Metadata,
    spec: S,
    status: T,
}

#[derive(Clone, Debug, Deserialize)]
struct PodSpec {
    containers: Vec<Container>,
}

#[derive(Clone, Debug, Deserialize)]
struct Container {
    name: String,
}

#[derive(Clone, Debug, Deserialize)]
struct PodStatus {
    #[serde(rename = "hostIP")]
    host_ip: Ipv4Addr,
    #[serde(rename = "podIP")]
    pod_ip: Option<Ipv4Addr>,
}

#[derive(Clone, Debug, Deserialize)]
struct NodeSpec {
    #[serde(rename = "podCIDR")]
    pod_cidr: cidr::Ipv4Cidr,
}

#[derive(Clone, Debug, Deserialize)]
struct NodeStatus {
    addresses: Vec<NodeAddress>,
}

impl NodeStatus {
    fn internal_addresses(&self) -> Vec<Ipv4Addr> {
        self.addresses
            .iter()
            .filter_map(|v| {
                if let NodeAddress::InternalIP { address } = v {
                    Some(address.to_owned())
                } else {
                    None
                }
            })
            .collect()
    }

    fn external_addresses(&self) -> Vec<Ipv4Addr> {
        self.addresses
            .iter()
            .filter_map(|v| {
                if let NodeAddress::ExternalIP { address } = v {
                    Some(address.to_owned())
                } else {
                    None
                }
            })
            .collect()
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
enum NodeAddress {
    InternalIP { address: Ipv4Addr },
    ExternalIP { address: Ipv4Addr },
    InternalDNS { address: String },
    Hostname { address: String },
}

type Selector = HashMap<String, String>;

#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "type")]
enum ServiceSpec {
    #[serde(rename = "ClusterIP")]
    ClusterIp {
        /// can be "None", in addition to None, no idea what that means
        #[serde(rename = "clusterIP")]
        cluster_ip: String,
        ports: Vec<Ports>,
        selector: Option<Selector>,
    },
    NodePort {
        #[serde(rename = "clusterIP")]
        cluster_ip: String,
        ports: Vec<Ports>,
        selector: Option<Selector>,
    },
    LoadBalancer {
        #[serde(rename = "clusterIP")]
        cluster_ip: String,
        ports: Vec<Ports>,
        selector: Option<Selector>,
    },
    #[serde(rename_all = "camelCase")]
    ExternalName { external_name: String },
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Ports {
    name: Option<String>,
    port: PortOrName,
    target_port: PortOrName,
    node_port: Option<PortOrName>,
}

#[derive(Clone, Debug)]
enum PortOrName {
    Port(u16),
    Name(String),
}

impl<'de> Deserialize<'de> for PortOrName {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Value::deserialize(deserializer)?;
        if let Some(port) = value.as_u64() {
            if let Ok(port) = u16::try_from(port) {
                return Ok(PortOrName::Port(port));
            }
        }

        if let Some(name) = value.as_str() {
            return Ok(PortOrName::Name(name.to_string()));
        }

        Err(serde::de::Error::custom(
            "PortOrName must be a port or a name",
        ))
    }
}
