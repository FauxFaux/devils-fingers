use std::convert::TryFrom;
use std::io;
use std::io::Write;
use std::net;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::mpsc;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::thread;
use std::time::Duration;
use std::time::Instant;

use etherparse::InternetSlice;
use etherparse::SlicedPacket;
use etherparse::TransportSlice;
use failure::err_msg;
use failure::Error;
use failure::ResultExt;

use crate::capture::pcap::pcap_pkthdr;
use crate::proto::Enc;
use crate::proto::Key;

mod pcap;

pub fn run_capture(master_key: Key, filter: &str, dest: &str, daemon: bool) -> Result<(), Error> {
    let dest = net::TcpStream::connect(dest)?;
    let dest = Enc::new(master_key.into(), dest)?;
    let dest = io::BufWriter::with_capacity(60 * 1024, dest);
    let mut dest = zstd::Encoder::new(dest, 3)?;
    let handle = pcap::PCap::open_with_filter("any", filter)
        .with_context(|_| err_msg("starting capture"))?;

    if daemon {
        println!("Running in background...");
        nix::unistd::daemon(false, false)?;
    }

    let running = Arc::new(AtomicBool::new(true));
    let in_handler = running.clone();
    let recv_loop = running.clone();

    ctrlc::set_handler(move || {
        in_handler.store(false, Ordering::SeqCst);
        println!("Attempting shutdown...");
    })?;

    let (sink, recv) = mpsc::sync_channel(128);

    let worker = thread::spawn(|| read_packets(handle, sink, running));

    let mut last_flush = Instant::now();

    while recv_loop.load(Ordering::SeqCst) {
        match recv.recv_timeout(Duration::from_secs(1)) {
            Ok(buf) => dest.write_all(&buf)?,
            Err(RecvTimeoutError::Timeout) => {
                let now = Instant::now();
                if now.duration_since(last_flush).as_secs() > 10 {
                    dest.flush()?;
                    last_flush = now;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }

    dest.finish()?;

    println!("File closed, may block until next packet...");

    // we're disconnected, so the worker has crashed/returned,
    // or we've been signaled to stop, so the worker should also stop (on next packet)
    worker
        .join()
        .expect("joining itself failed")
        .with_context(|_| err_msg("worker failed"))?;

    println!("Done.");

    Ok(())
}

fn read_packets(
    mut handle: pcap::PCap,
    sink: mpsc::SyncSender<[u8; 512]>,
    running: Arc<AtomicBool>,
) -> Result<(), Error> {
    while running.load(Ordering::SeqCst) {
        let (header, data) = match handle.next() {
            Some(d) => d,
            None => continue,
        };

        if let Some(record) = pack_mostly_data(header, data)? {
            // err: disconnected
            if sink.send(record).is_err() {
                break;
            }
        }
    }

    Ok(())
}

fn pack_mostly_data(header: &pcap_pkthdr, data: &[u8]) -> Result<Option<[u8; 512]>, Error> {
    let ts = {
        u64::try_from(
            header
                .ts
                .tv_sec
                .checked_mul(1_000_000)
                .ok_or_else(|| err_msg("tv_sec out of range"))?
                .checked_add(header.ts.tv_usec)
                .ok_or_else(|| err_msg("tv_sec+tv_usec out of range"))?,
        )?
    };

    // it's probably right, I promise
    if data.len() < 36 {
        return Ok(None);
    }

    // classic pcap
    let data = &data[2..];

    // discard ethernet header
    let data = &data[14..];

    let packet = match SlicedPacket::from_ip(data) {
        Ok(packet) => packet,
        _ => return Ok(None),
    };

    let t = match packet.transport {
        Some(TransportSlice::Tcp(t)) => t,
        _ => return Ok(None),
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
        return Ok(None);
    }

    let (src_ip, dest_ip) = match packet.ip {
        Some(InternetSlice::Ipv4(ref v)) => (v.source(), v.destination()),
        _ => return Ok(None),
    };

    let mut record = [0u8; 512];
    record[..8].copy_from_slice(&ts.to_le_bytes());
    record[8..12].copy_from_slice(src_ip);
    record[12..14].copy_from_slice(&t.source_port().to_le_bytes());
    record[14..18].copy_from_slice(dest_ip);
    const HEADER_END: usize = 20;
    record[18..HEADER_END].copy_from_slice(&t.destination_port().to_le_bytes());
    let usable = (data.len()).min(record.len() - HEADER_END);
    record[HEADER_END..HEADER_END + usable].copy_from_slice(&data[..usable]);

    Ok(Some(record))
}
