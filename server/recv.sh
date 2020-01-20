#!/bin/sh
set -eu

lo_port=21461
new_file="$(dirname "$0")"/new-file.sh

if ! [ -x "$new_file" ]; then
  echo "Failed to guess helper location: $new_file"
  exit 4
fi

if [ -z "${PCAP_MASTER_KEY+x}" ]; then
  echo "PCAP_MASTER_KEY must be set"
  exit 5
fi

printf "%s" "$PCAP_MASTER_KEY" | spiped -F -k - -d -s 0.0.0.0:1773 -t localhost:${lo_port} &
SPIPE_PID=$!
trap "kill "$SPIPE_PID EXIT

socat tcp-listen:${lo_port},reuseaddr,fork exec:${new_file}
