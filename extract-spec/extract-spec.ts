#!ts-node --compiler-options={"resolveJsonModule":true}

// while true; do echo '{"now": "'$(date -Is)'", "po":' $(kc get po --all-namespaces -o json) ',"no":' $(kc get no --all-namespaces -o json) ',"svc":' $(kc get svc --all-namespaces -o json) '}' | jq -c .; sleep 3600; done >> spec.json

import * as spec from './spec.json';

const nodes = [];
const pods = [];
const services = [];

for (const no of spec.no.items) {
  nodes.push({
    name: no.metadata.name,
    created: no.metadata.creationTimestamp,
    podCidr: no.spec.podCIDR,
    internalIp: find_where(no.status.addresses, 'type', 'InternalIP').address,
    externalIp: find_where(no.status.addresses, 'type', 'ExternalIP').address,
  });
}

for (const svc of spec.svc.items) {
  if ('ClusterIP' !== svc.spec.type || 'None' === svc.spec.clusterIP) {
    continue;
  }

  services.push({
    name: svc.metadata.name,
    created: svc.metadata.creationTimestamp,
    ip: svc.spec.clusterIP,
  });
}

for (const po of spec.po.items) {
  pods.push({
    name: po.metadata.labels.name,
    nameFirstContainer: po.spec.containers[0].name,
    created: po.metadata.creationTimestamp,
    nodeIp: po.status.hostIP,
    podIp: po.status.podIP,
  });
}

console.log(JSON.stringify({ now: spec.now, nodes, pods, services }));

function find_where(list, key, value) {
  for (const obj of list) {
    if (obj[key] === value) {
      return obj;
    }
  }
  throw new Error('not found');
}
