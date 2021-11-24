use crate::uname::Uname;
use std::io;

impl Uname {
    pub fn new() -> io::Result<Uname> {
        let uname = Uname {
            sys_name: String::from("Windows"),
            node_name: String::from("unknown"),
            release: String::from("unknown"),
            version: String::from("unknown"),
            // TODO: need optimized with real arch.
            machine: String::from("i686"),
        };
        return Ok(uname);
    }
}
