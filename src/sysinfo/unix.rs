use crate::sysinfo::Uname;
use std::ffi::CStr;
use std::io;

use libc::{c_char, utsname};

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
    s.to_string_lossy().into_owned().replace("\"", "\\\"")
}

impl From<utsname> for Uname {
    fn from(x: utsname) -> Self {
        let uname = Uname {
            sys_name: parse(&x.sysname),
            release: parse(&x.release),
            version: parse(&x.version),
            machine: parse(&x.machine),
        };
        uname
    }
}

pub fn get_hostname() -> Option<String> {
    let size = unsafe { libc::sysconf(libc::_SC_HOST_NAME_MAX) as libc::size_t };
    let mut buffer = vec![0u8; size + 1];
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr() as *mut libc::c_char, size) };
    if result != 0 {
        return None;
    }
    let len = (0..usize::MAX)
        .position(|i| buffer[i] == 0)
        .expect("out of range");

    Some(String::from_utf8_lossy(&buffer[0..len]).to_string())
}
