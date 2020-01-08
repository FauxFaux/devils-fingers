use std::slice;

use etherparse::{InternetSlice, SlicedPacket, TransportSlice};

mod pcap;

fn main() {
    let handle = unsafe { pcap::open_with_filter() };

    loop {
        let (header, data) = unsafe { pcap::next(handle) };
        let data = unsafe { slice::from_raw_parts(data, (*header).len as usize) };

        match SlicedPacket::from_ip(&data[2 + 14..]) {
            Err(value) => println!("Err {:?}", value),
            Ok(value) => {
                match value.ip {
                    Some(InternetSlice::Ipv4(ref v)) => {
                        println!("{} {}", v.source_addr(), v.destination_addr())
                    }
                    _ => continue,
                }
                let t = match value.transport {
                    Some(TransportSlice::Tcp(t)) => t,
                    _ => continue,
                };

                println!("{} {}", t.source_port(), t.destination_port());
                let header_end = usize::from(t.data_offset()) * 4;
                println!("{}", String::from_utf8_lossy(&data[36 + header_end..]));
            }
        }
    }
}
