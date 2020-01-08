#![allow(non_camel_case_types)]

use std::ffi::CString;
use std::mem;
use std::ptr;

use libc::{c_char, c_int, c_uchar, c_uint, c_ushort, timeval};

pub enum pcap_t {}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_program {
    pub bf_len: c_uint,
    pub bf_insns: *mut bpf_insn,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct bpf_insn {
    pub code: c_ushort,
    pub jt: c_uchar,
    pub jf: c_uchar,
    pub k: c_uint,
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
    pub fn pcap_open_live(
        device: *const c_char,
        buffer_size: c_int,
        promiscuous: c_int,
        timout_ms: c_int,
        err: *mut c_char,
    ) -> *mut pcap_t;
    pub fn pcap_compile(
        arg1: *mut pcap_t,
        arg2: *mut bpf_program,
        arg3: *const c_char,
        arg4: c_int,
        arg5: c_uint,
    ) -> c_int;
    pub fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> c_int;
    pub fn pcap_next_ex(
        arg1: *mut pcap_t,
        arg2: *mut *mut pcap_pkthdr,
        arg3: *mut *const c_uchar,
    ) -> c_int;
}

pub unsafe fn open_with_filter() -> *mut pcap_t {
    let device = CString::new("any").unwrap();
    let mut err = [0 as c_char; 4096];
    let handle = pcap_open_live(device.as_ptr(), 8096, 1, 1000, err.as_mut_ptr());
    assert!(!handle.is_null());
    let prog = CString::new("port 80").unwrap();
    let mut bpf = mem::zeroed();
    assert_ne!(-1, pcap_compile(handle, &mut bpf, prog.as_ptr(), 0, 0));
    assert_ne!(-1, pcap_setfilter(handle, &mut bpf));
    handle
}

pub unsafe fn next(handle: *mut pcap_t) -> Option<(*mut pcap_pkthdr, *const c_uchar)> {
    let mut header: *mut pcap_pkthdr = ptr::null_mut();
    let mut buf: *const c_uchar = ptr::null();
    if 1 != pcap_next_ex(handle, &mut header, &mut buf) {
        return None;
    }
    Some((header, buf))
}
