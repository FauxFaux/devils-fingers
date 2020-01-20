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

use crate::buffer::Buffer;
use crate::capture::pcap::pcap_pkthdr;
use crate::proto::Enc;
use crate::proto::Key;

mod pcap;

pub fn run_capture<F>(
    master_key: Key,
    filter: &str,
    dest: &str,
    daemon: bool,
    packer: F,
) -> Result<(), Error>
where
    F: 'static + Send + Fn(&pcap_pkthdr, &[u8]) -> Result<Buffer, Error>,
{
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

    let worker = thread::spawn(|| read_packets(handle, sink, running, packer));

    let mut last_flush = Instant::now();

    while recv_loop.load(Ordering::SeqCst) {
        match recv.recv_timeout(Duration::from_secs(1)) {
            Ok(buf) => {
                dest.write_all(&u16::try_from(buf.len())?.to_le_bytes())?;
                dest.write_all(buf.as_ref())?;
            }
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

fn read_packets<F>(
    mut handle: pcap::PCap,
    sink: mpsc::SyncSender<Buffer>,
    running: Arc<AtomicBool>,
    packer: F,
) -> Result<(), Error>
where
    F: Fn(&pcap_pkthdr, &[u8]) -> Result<Buffer, Error>,
{
    let mut previous = Buffer::empty();
    while running.load(Ordering::SeqCst) {
        let (header, data) = match handle.next() {
            Some(d) => d,
            None => continue,
        };

        let buffer = packer(header, data)?;
        if buffer.is_empty() {
            continue;
        }

        if buffer.as_ref() == previous.as_ref() {
            continue;
        }

        previous = buffer;

        // err: disconnected
        if sink.send(buffer).is_err() {
            break;
        }
    }

    Ok(())
}

pub fn pack_mostly_data(header: &pcap_pkthdr, data: &[u8]) -> Result<Buffer, Error> {
    // it's probably right, I promise
    if data.len() < 36 {
        return Ok(Buffer::empty());
    }

    // classic pcap
    let data = &data[2..];

    // discard ethernet header
    let data = &data[14..];

    let packet = match SlicedPacket::from_ip(data) {
        Ok(packet) => packet,
        _ => return Ok(Buffer::empty()),
    };

    let (src_ip, dest_ip) = match packet.ip {
        Some(InternetSlice::Ipv4(ref v)) => (v.source(), v.destination()),
        _ => return Ok(Buffer::empty()),
    };

    let t = match packet.transport {
        Some(TransportSlice::Tcp(t)) => t,
        _ => return Ok(Buffer::empty()),
    };

    let header_end = usize::from(t.data_offset()) * 4;

    let data = &data[20 + header_end..];

    if !(t.syn()
        || t.fin()
        || t.rst()
        || data.starts_with(b"GET /")
        || data.starts_with(b"POST /")
        || data.starts_with(b"PUT /")
        || data.starts_with(b"HTTP/1.1 ")
        || data.starts_with(b"HEAD /")
        || data.starts_with(b"DELETE /"))
    {
        return Ok(Buffer::empty());
    }

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

    let tcp_flags = t.slice()[13];

    let mut record = Buffer::empty();
    record.push_u64(ts);
    record.extend_from_slice(src_ip);
    record.push_u16(t.source_port());
    record.extend_from_slice(dest_ip);
    record.push_u16(t.destination_port());
    record.push_u8(tcp_flags);
    assert_eq!(21, record.len());
    let usable = (data.len()).min(record.capacity() - record.len());
    record.extend_from_slice(&data[..usable]);

    Ok(record)
}

pub fn pack_pcap_legacy_format(header: &pcap_pkthdr, data: &[u8]) -> Result<Buffer, Error> {
    let mut record = Buffer::empty();

    let ts_sec = u32::try_from(header.ts.tv_sec)?;
    let ts_usec = u32::try_from(header.ts.tv_usec)?;
    let usable = (data.len()).min(record.capacity() - 16);
    let included_len = u32::try_from(usable)?;
    let original_len = header.len;

    record.push_u32(ts_sec);
    record.push_u32(ts_usec);
    record.push_u32(included_len);
    record.push_u32(original_len);
    assert_eq!(16, record.len());
    record.extend_from_slice(&data[..usable]);

    Ok(record)
}
