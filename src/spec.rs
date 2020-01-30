use std::collections::HashMap;
use std::convert::TryFrom;
use std::io::Read;
use std::net::Ipv4Addr;

use cidr::Cidr;
use cidr::Ipv4Cidr;
use failure::Error;
use serde::Deserialize;
use serde::Deserializer;
use serde_derive::Deserialize;
use serde_json::Value;

type Date = chrono::DateTime<chrono::Utc>;

pub type Spec = Together;

pub fn load<R: Read>(rdr: R) -> impl Iterator<Item = Result<Together, serde_json::Error>> {
    serde_json::Deserializer::from_reader(rdr).into_iter()
}

impl Together {
    pub fn name(&self, addr_net: &Ipv4Addr) -> String {
        let addr = addr_net.to_string();
        for service in &self.svc.items {
            if let ServiceSpec::ClusterIp { cluster_ip, .. } = &service.spec {
                if cluster_ip == &addr {
                    return format!("svc:{}", service.metadata.name);
                }
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
            if node.status.internal_addresses().contains(addr_net) {
                return format!("int:node:{}", i);
            }

            if node.status.external_addresses().contains(addr_net) {
                return format!("ext:node:{}", i);
            }

            if node.spec.pod_cidr.contains(addr_net) {
                return format!("p@{}:{}", i, addr_net);
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
    name: String,
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
