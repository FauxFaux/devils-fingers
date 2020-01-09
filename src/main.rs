use std::env;
use std::fs;
use std::io::Write;
use std::slice;

use etherparse::InternetSlice;
use etherparse::SlicedPacket;
use etherparse::TransportSlice;
use failure::err_msg;
use failure::Error;
use failure::ResultExt;

mod pcap;

fn main() -> Result<(), Error> {
    let args = clap::App::new(clap::crate_name!())
        .arg(clap::Arg::with_name("daemon").long("daemon"))
        .arg(
            clap::Arg::with_name("dest")
                .long("dest")
                .takes_value(true)
                .required(true),
        )
        .get_matches();
    let file = fs::File::create(
        args.value_of_os("dest")
            .ok_or_else(|| err_msg("usage: dest file"))?,
    )?;
    let mut file = zstd::Encoder::new(file, 3)?;
    let handle =
        pcap::open_with_filter("any", "port 80").with_context(|_| err_msg("starting capture"))?;

    if args.is_present("daemon") {
        println!("Running in background...");
        nix::unistd::daemon(false, false)?;
    }

    let mut written = 0u8;

    loop {
        // unsafe: these pointers are only valid until the
        // next call to `next` (or other currently not exposed functions)
        let (header, data) = match unsafe { pcap::next(handle) } {
            Some(d) => d,
            None => continue,
        };
        let libc::timeval { tv_sec, tv_usec } = unsafe { (*header).ts };
        let _: i64 = tv_sec;
        let _: i64 = tv_usec;

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

        let mut record = [0u8; 8 + 8 + 4 + 4 + 2 + 2 + 228];
        record[..8].copy_from_slice(&tv_sec.to_le_bytes());
        record[8..16].copy_from_slice(&tv_usec.to_le_bytes());
        record[16..20].copy_from_slice(src_ip);
        record[20..24].copy_from_slice(dest_ip);
        record[24..26].copy_from_slice(&t.source_port().to_le_bytes());
        const HEADER_END: usize = 28;
        record[26..HEADER_END].copy_from_slice(&t.destination_port().to_le_bytes());
        let usable = (data.len()).min(record.len() - HEADER_END);
        record[HEADER_END..HEADER_END + usable].copy_from_slice(&data[..usable]);

        file.write_all(&record)?;

        written += 1;

        if written == 255 {
            file.flush()?;
            written = 0;
        }
    }
}
