use std::collections::HashMap;
use std::convert::TryFrom;
use std::fs;
use std::io::Read;
use std::net::Ipv4Addr;

use cidr::Cidr;
use failure::Error;
use serde_derive::Deserialize;
use serde_json::Value;

type Date = chrono::DateTime<chrono::Utc>;

pub type Spec = Together;

pub fn load<R: Read>(rdr: R) -> Result<Together, Error> {
    Ok(serde_json::from_reader(rdr)?)
}

impl Together {
    pub fn name(&self, addr_net: &Ipv4Addr) -> String {
        let addr = addr_net.to_string();
        for service in &self.svc.items {
            if service.spec.cluster_ip.unwrap_or(String::new()) == addr {
                return format!("svc:{}", service.metadata.name);
            }
        }

        for pod in &self.po.items {
            let spec = &pod.spec;
            let status = &pod.status;
            if status.pod_ip != status.host_ip && status.pod_ip == addr {
                return pod
                    .metadata
                    .labels
                    .name
                    .(spec.containers.get(0)?.name)
                    .to_string();
            }
        }

        for (i, node) in self.no.iter().enumerate() {
            if node.internal_ip == addr {
                return format!("int:node:{}", i);
            }

            if node.external_ip == addr {
                return format!("ext:node:{}", i);
            }

            if let Ok(cidr) = node.pod_cidr.parse::<cidr::Ipv4Cidr>() {
                if cidr.contains(addr_net) {
                    return format!("unknown-pod-node:{}", i);
                }
            }
        }

        addr
    }
}

#[derive(Clone, Debug, Deserialize)]
struct Nah {}

#[derive(Clone, Debug, Deserialize)]
struct Together {
    now: Date,
    po: ListDoc<PodSpec, PodStatus>,
    no: ListDoc<NodeSpec, Nah>,
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
    pod_ip: Ipv4Addr,
}

#[derive(Clone, Debug, Deserialize)]
struct NodeSpec {}

// sigh enum renames?
type ServiceType = String;

#[derive(Clone, Debug, Deserialize)]
struct ServiceSpec {
    #[serde(rename = "clusterIP")]
    /// iff type field is ClusterIP, but
    /// can be "None", in addition to None, no idea what that means
    cluster_ip: Option<String>,
    #[serde(rename = "type")]
    service_type: ServiceType,
}

fn load_cluster_ip(value: &str) -> Option<Ipv4Addr> {
    None
}

fn find_address(addresses: &[Value], key: &str) -> Option<String> {
    for address in addresses {
        if address.get("type")?.as_str()? == key {
            return Some(address.get("address")?.as_str()?.to_string());
        }
    }

    None
}
