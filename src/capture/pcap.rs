#![allow(non_camel_case_types)]

use std::ffi::CString;
use std::mem;
use std::ptr;
use std::slice;

use anyhow::ensure;
use anyhow::Error;
use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, timeval};

enum pcap_t {}

pub struct PCap {
    inner: *mut pcap_t,
}

impl Drop for PCap {
    fn drop(&mut self) {
        unsafe { pcap_close(self.inner) };
        self.inner = ptr::null_mut();
    }
}

unsafe impl Send for PCap {}

#[repr(C)]
#[derive(Copy, Clone)]
struct bpf_program {
    bf_len: c_uint,
    bf_insns: *mut bpf_insn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_insn {
    code: c_ushort,
    jt: c_uchar,
    jf: c_uchar,
    k: c_uint,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct pcap_pkthdr {
    pub ts: timeval,
    pub caplen: c_uint,
    pub len: c_uint,
}

#[link(name = "pcap")]
extern "C" {
    fn pcap_open_live(
        device: *const c_char,
        buffer_size: c_int,
        promiscuous: c_int,
        timout_ms: c_int,
        err: *mut c_char,
    ) -> *mut pcap_t;
    fn pcap_close(handle: *mut pcap_t);
    fn pcap_compile(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const c_char,
        arg4: c_int,
        arg5: c_uint,
    ) -> c_int;
    fn pcap_freecode(arg1: *mut bpf_program);
    fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int;
    fn pcap_next_ex(
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const c_uchar,
    ) -> c_int;
}

impl PCap {
    pub fn open_with_filter(device: &str, filter: &str) -> Result<PCap, Error> {
        let device = CString::new(device)?;
        let mut err = [0 as c_char; 4096];
        let handle = unsafe { pcap_open_live(device.as_ptr(), 512, 1, 1000, err.as_mut_ptr()) };
        ensure!(!handle.is_null(), "open failed: {}", pcap_msg(&err));
        let mut handle = PCap { inner: handle };

        let mut prog = Prog::new_for(&mut handle, filter)?;

        ensure!(
            0 == unsafe { pcap_setfilter(handle.inner, &mut prog.inner) },
            "set failed"
        );

        Ok(handle)
    }

    pub fn next(&mut self) -> Option<(&pcap_pkthdr, &[u8])> {
        let mut header: *mut pcap_pkthdr = ptr::null_mut();
        let mut buf: *const c_uchar = ptr::null();
        if 1 != unsafe { pcap_next_ex(self.inner, &mut header, &mut buf) } {
            return None;
        }

        assert!(!header.is_null());
        assert!(!buf.is_null());

        // unsafe: valid until the next call to certain methods (such as pcap_next_ex) on the handle,
        // which is blocked by us having a &mut borrow of it
        let header = unsafe { &*header };

        // unsafe: as above, and the length is specified by the API
        let buf = unsafe { slice::from_raw_parts(buf, (*header).caplen as usize) };

        Some((header, buf))
    }
}

struct Prog {
    inner: bpf_program,
}

impl Prog {
    fn new_for(handle: &mut PCap, code: &str) -> Result<Prog, Error> {
        let prog = CString::new(code)?;
        let mut bpf = unsafe { mem::zeroed() };
        ensure!(
            0 == unsafe { pcap_compile(handle.inner, &mut bpf, prog.as_ptr(), 1, 0) },
            "compile failed"
        );
        Ok(Prog { inner: bpf })
    }
}

impl Drop for Prog {
    fn drop(&mut self) {
        unsafe { pcap_freecode(&mut self.inner) };
        self.inner = unsafe { mem::zeroed() };
    }
}

fn pcap_msg(err: &[i8]) -> String {
    let err = unsafe { &*(err as *const _ as *const [u8]) };
    let end = err
        .iter()
        .position(|&c| 0 == c)
        .unwrap_or_else(|| err.len());
    String::from_utf8_lossy(&err[..end]).to_string()
}
