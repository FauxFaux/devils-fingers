use std::env;
use std::fs;
use std::io;
use std::io::Write;
use std::slice;

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

mod pcap;

fn main() {
    let mut file = io::BufWriter::new(
        fs::File::create(env::args_os().nth(1).expect("usage: dest file")).expect("creating file"),
    );
    let handle = unsafe { pcap::open_with_filter() };

    loop {
        let (header, data) = match unsafe { pcap::next(handle) } {
            Some(d) => d,
            None => {
                eprintln!("error");
                continue;
            }
        };
        let data = unsafe { slice::from_raw_parts(data, (*header).caplen as usize) };

        // it's probably right, I promise
        if data.len() < 36 {
            continue;
        }

        // classic pcap
        let data = &data[2..];

        // discard ethernet header
        let data = &data[14..];

        let packet = match SlicedPacket::from_ip(data) {
            Ok(packet) => packet,
            _ => continue,
        };

        let t = match packet.transport {
            Some(TransportSlice::Tcp(t)) => t,
            _ => continue,
        };

        let header_end = usize::from(t.data_offset()) * 4;

        let data = &data[20 + header_end..];

        if !(data.starts_with(b"GET /")
            || data.starts_with(b"POST /")
            || data.starts_with(b"PUT /")
            || data.starts_with(b"HTTP/1.1 ")
            || data.starts_with(b"HEAD /")
            || data.starts_with(b"DELETE /"))
        {
            continue;
        }

        let (src_ip, dest_ip) = match packet.ip {
            Some(InternetSlice::Ipv4(ref v)) => (v.source(), v.destination()),
            _ => continue,
        };

        let mut record = [0u8; 4 + 4 + 2 + 2 + 116];
        record[..4].copy_from_slice(src_ip);
        record[4..8].copy_from_slice(dest_ip);
        record[8..10].copy_from_slice(&t.source_port().to_le_bytes());
        record[10..12].copy_from_slice(&t.destination_port().to_le_bytes());
        let usable = (data.len()).min(record.len() - 12);
        record[12..12 + usable].copy_from_slice(&data[..usable]);

        file.write_all(&record).expect("writing output");
    }
}
