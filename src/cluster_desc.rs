use std::io::Read;

use anyhow::Error;
use cidr::Ipv4Cidr;
use serde_derive::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct ClusterDesc {
    /// The range from which nodes are allocated, e.g. `10.128.0.0/9` for the whole of GCE,
    /// c.f. https://cloud.google.com/vpc/docs/vpc
    node_range: Ipv4Cidr,

    /// The range from which pods are allocated,
    /// i.e. `gcloud container clusters describe my-cluster`'s `clusterIpv4Cidr`,
    /// e.g. `10.69.0.0/14`
    pod_range: Ipv4Cidr,

    /// Assume each node is allocated a pod cidr of this, e.g. `/24`.
    /// (Useful for finding out if an address is the gateway; the second address in a range.)
    /// See the `podIpv4CidrSize` value, or that `--default-max-pods-per-node=110`.
    /// https://cloud.google.com/kubernetes-engine/docs/how-to/flexible-pod-cidr
    assume_node_pod_cidr: u8,

    /// The range from which services are allocated, i.e. the describe's `servicesIpv4Cidr`,
    /// this is typically the last `/20` of the `pod_range`, e.g. `10.71.240/20`.
    services_range: Option<Ipv4Cidr>,
}

impl ClusterDesc {
    pub fn from_reader<R: Read>(mut reader: R) -> Result<ClusterDesc, Error> {
        let mut buf = String::with_capacity(256);
        reader.read_to_string(&mut buf)?;
        Ok(toml::from_str(&buf)?)
    }
}
