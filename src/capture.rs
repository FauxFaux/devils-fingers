use std::io;
use std::io::Write;
use std::net;
use std::slice;
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

use crate::proto::Enc;
use crate::proto::Key;

mod pcap;

pub fn run_capture(master_key: Key, filter: &str, dest: &str, daemon: bool) -> Result<(), Error> {
    let dest = net::TcpStream::connect(dest)?;
    let dest = Enc::new(master_key.into(), dest)?;
    let dest = io::BufWriter::with_capacity(60 * 1024, dest);
    let mut dest = zstd::Encoder::new(dest, 3)?;
    let handle =
        pcap::open_with_filter("any", filter).with_context(|_| err_msg("starting capture"))?;

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
    sink: mpsc::SyncSender<[u8; 256]>,
    running: Arc<AtomicBool>,
) -> Result<(), Error> {
    while running.load(Ordering::SeqCst) {
        // unsafe: these pointers are only valid until the
        // next call to `next` (or other currently not exposed functions)
        let (header, data) = match unsafe { pcap::next(&mut handle) } {
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

        // err: disconnected
        if sink.send(record).is_err() {
            break;
        }
    }

    Ok(())
}
