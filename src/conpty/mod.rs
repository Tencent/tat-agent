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

pub const WS_TXT_MSG: &str = "pty_cmd_msg";
pub const WS_BIN_MSG: &str = "pty_file_msg";
pub const PTY_INSPECT_READ: u8 = 0x0;
pub const PTY_INSPECT_WRITE: u8 = 0x1;
pub const SLOT_PTY_BIN: &str = "event_slot_pty_file";
pub const WS_MSG_TYPE_PTY_ERROR: &str = "PtyError";
pub const PTY_FLAG_ENABLE_BLOCK: u32 = 0x00000001;

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
