use std::collections::HashMap;
use std::io::Read;
use std::net::Ipv4Addr;

use cidr::Cidr;
use failure::Error;
use serde_derive::Deserialize;

type Date = chrono::DateTime<chrono::Utc>;

pub type Spec = Together;

pub fn load<R: Read>(rdr: R) -> Result<Together, Error> {
    Ok(serde_json::from_reader(rdr)?)
}

impl Together {
    pub fn name(&self, addr_net: &Ipv4Addr) -> String {
        let addr = addr_net.to_string();
        for service in &self.svc.items {
            if service.spec.cluster_ip.as_ref().unwrap_or(&String::new()) == &addr {
                return format!("svc:{}", service.metadata.name);
            }
        }

        for pod in &self.po.items {
            let spec = &pod.spec;
            let status = &pod.status;
            if status.pod_ip != status.host_ip && status.pod_ip == *addr_net {
                if let Some(labels) = pod.metadata.labels.as_ref() {
                    if let Some(name) = labels.get("name") {
                        return name.to_string();
                    }
                }

                if let Some(container) = spec.containers.get(0) {
                    return container.name.to_string();
                }
            }
        }

        for (i, node) in self.no.items.iter().enumerate() {
            if find_address(&node.status.addresses, "InternalIP") == Some(*addr_net) {
                return format!("int:node:{}", i);
            }

            if find_address(&node.status.addresses, "ExternalIP") == Some(*addr_net) {
                return format!("ext:node:{}", i);
            }

            if node.spec.pod_cidr.contains(addr_net) {
                return format!("unknown-pod-node:{}", i);
            }
        }

        addr
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
    pod_ip: Ipv4Addr,
}

#[derive(Clone, Debug, Deserialize)]
struct NodeSpec {
    pod_cidr: cidr::Ipv4Cidr,
}

#[derive(Clone, Debug, Deserialize)]
struct NodeStatus {
    addresses: Vec<NodeAddress>,
}

#[derive(Clone, Debug, Deserialize)]
struct NodeAddress {
    #[serde(rename = "type")]
    address_type: String,
    address: Ipv4Addr,
}

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

fn find_address(addresses: &[NodeAddress], key: &str) -> Option<Ipv4Addr> {
    for address in addresses {
        if address.address_type == key {
            return Some(address.address.to_owned());
        }
    }

    None
}
