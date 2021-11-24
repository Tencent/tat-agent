use std::io;
use std::ffi::CStr;

use libc::{utsname, c_char};
use crate::uname::Uname;

impl Uname {
    pub fn new() -> io::Result<Uname> {
        let mut n = unsafe { std::mem::zeroed() };
        let r = unsafe { libc::uname(&mut n) };
        if r == 0 {
            Ok(From::from(n))
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[inline]
fn parse(buf: &[c_char]) -> String {
    let s = unsafe { CStr::from_ptr(buf.as_ptr()) };
    s.to_string_lossy().into_owned().replace("\"","\\\"")
}

impl From<utsname> for Uname {
    fn from(x: utsname) -> Self {
        let uname = Uname {
            sys_name: parse(&x.sysname),
            node_name: parse(&x.nodename),
            release: parse(&x.release),
            version: parse(&x.version),
            machine: parse(&x.machine),
        };
        uname
    }
}
