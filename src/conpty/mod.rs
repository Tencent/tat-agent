use std::{fs::File, sync::Arc};
mod file;
pub mod gather;
mod handler;
mod proxy;
mod pty;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
    } else if #[cfg(windows)] {
        mod windows;
        mod bind;
        mod parser;
    }
}

pub const PTY_INSPECT_READ: u8 = 0x0;
pub const PTY_INSPECT_WRITE: u8 = 0x1;

pub trait PtyAdapter {
    fn openpty(
        &self,
        user_name: &str,
        cols: u16,
        rows: u16,
        flag: u32,
    ) -> Result<Arc<dyn PtyBase + Send + Sync>, String>;
}
pub trait PtyBase {
    fn resize(&self, cols: u16, rows: u16) -> Result<(), String>;
    fn get_reader(&self) -> Result<File, String>;
    fn get_writer(&self) -> Result<File, String>;
    fn get_pid(&self) -> Result<u32, String>;
    fn inspect_access(&self, path: &str, access: u8) -> Result<(), String>;
    fn execute(&self, f: &dyn Fn() -> Result<Vec<u8>, String>) -> Result<Vec<u8>, String>;
}
