use std::convert::TryFrom;
use std::fs;
use std::net::Ipv4Addr;

use cidr::Cidr;
use failure::Error;
use serde_derive::Deserialize;

type Date = chrono::DateTime<chrono::Utc>;

#[derive(Clone, Debug, Deserialize)]
pub struct Spec {
    now: Date,
    nodes: Vec<Node>,
    pods: Vec<Pod>,
    services: Vec<Service>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Node {
    name: String,
    created: Date,
    pod_cidr: String,
    internal_ip: String,
    external_ip: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Pod {
    name: Option<String>,
    name_first_container: String,
    created: Date,
    node_ip: String,
    pod_ip: String,
}

#[derive(Clone, Debug, Deserialize)]
struct Service {
    name: String,
    created: Date,
    ip: String,
}

pub fn load() -> Result<Spec, Error> {
    let file = fs::File::open("short-spec.json")?;
    Ok(serde_json::from_reader(file)?)
}

impl Spec {
    pub fn name(&self, addr_net: &Ipv4Addr) -> String {
        let addr = addr_net.to_string();
        for service in &self.services {
            if service.ip == addr {
                return format!("svc:{}", service.name);
            }
        }

        for pod in &self.pods {
            if pod.pod_ip != pod.node_ip && pod.pod_ip == addr {
                return pod
                    .name
                    .as_ref()
                    .unwrap_or(&pod.name_first_container)
                    .to_string();
            }
        }

        for (i, node) in self.nodes.iter().enumerate() {
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
