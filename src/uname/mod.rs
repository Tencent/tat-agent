pub mod common;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub struct Uname {
    sys_name: String,
    node_name: String,
    release: String,
    version: String,
    machine: String,
}
