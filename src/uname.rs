pub mod common;
#[cfg(windows)]
mod windows;
#[cfg(unix)]
mod unix;

pub struct Uname {
    sys_name: String,
    node_name: String,
    release: String,
    version: String,
    machine: String,
}
