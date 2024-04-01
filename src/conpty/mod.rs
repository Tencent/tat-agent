use std::{fs::File, sync::Arc};

use tokio::process::Command;

mod file;
pub mod gather;
mod handler;
mod proxy;
mod pty;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub use unix::ConPtyAdapter;
        mod unix;
    } else if #[cfg(windows)] {
        pub use windows::ConPtyAdapter;
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
pub const PTY_FLAG_ENABLE_BLOCK: u32 = 0x00000001;
#[cfg(not(test))]
pub const PTY_EXEC_DATA_SIZE: usize = 2048;
#[cfg(test)]
pub const PTY_EXEC_DATA_SIZE: usize = 5;

const WS_MSG_TYPE_PTY_ERROR: &str = "PtyError";
const WS_MSG_TYPE_PTY_EXEC_CMD: &str = "PtyExecCmd";
const WS_MSG_TYPE_PTY_EXEC_CMD_STREAM: &str = "PtyExecCmdStream";
const WS_MSG_TYPE_PTY_START: &str = "PtyStart";
const WS_MSG_TYPE_PTY_STOP: &str = "PtyStop";
const WS_MSG_TYPE_PTY_RESIZE: &str = "PtyResize";
const WS_MSG_TYPE_PTY_INPUT: &str = "PtyInput";
const WS_MSG_TYPE_PTY_READY: &str = "PtyReady";
const WS_MSG_TYPE_PTY_OUTPUT: &str = "PtyOutput";

type PtyExecCallback = Box<dyn Fn(u32, bool, Option<i32>, Vec<u8>)>;
type PtyResult<T> = Result<T, String>;

pub trait PtyAdapter {
    fn openpty(
        user_name: &str,
        cols: u16,
        rows: u16,
        flag: u32,
    ) -> PtyResult<Arc<dyn PtyBase + Send + Sync>>;
}

pub trait PtyBase {
    fn resize(&self, cols: u16, rows: u16) -> PtyResult<()>;
    fn get_reader(&self) -> PtyResult<File>;
    fn get_writer(&self) -> PtyResult<File>;
    fn get_pid(&self) -> PtyResult<u32>;
    fn inspect_access(&self, path: &str, access: u8) -> PtyResult<()>;
    fn execute(&self, f: &dyn Fn() -> PtyResult<Vec<u8>>) -> PtyResult<Vec<u8>>;
    fn execute_stream(
        &self,
        cmd: Command,
        cb: Option<PtyExecCallback>,
        timeout: Option<u64>,
    ) -> PtyResult<()>;
}
