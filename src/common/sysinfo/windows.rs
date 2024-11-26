use crate::common::{sysinfo::Uname, wsz2string};

use std::{io, ptr};

use winapi::um::sysinfoapi::{ComputerNamePhysicalDnsHostname, GetComputerNameExW};

impl Uname {
    pub fn new() -> io::Result<Uname> {
        let uname = Uname {
            sys_name: String::from("Windows"),
            release: String::from("unknown"),
            version: String::from("unknown"),
            // TODO: need optimized with real arch.
            machine: String::from("x86_64"),
        };
        return Ok(uname);
    }
}

pub fn get_hostname() -> Option<String> {
    let mut size = 0;
    unsafe {
        let result =
            GetComputerNameExW(ComputerNamePhysicalDnsHostname, ptr::null_mut(), &mut size);
        debug_assert_eq!(result, 0);
    };

    let mut buffer = Vec::with_capacity(size as usize);
    let result = unsafe {
        GetComputerNameExW(
            ComputerNamePhysicalDnsHostname,
            buffer.as_mut_ptr(),
            &mut size,
        )
    };

    if result == 0 {
        return None;
    }
    unsafe {
        buffer.set_len(size as usize);
        Some(wsz2string(buffer.as_ptr()))
    }
}
