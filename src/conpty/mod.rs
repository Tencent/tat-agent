mod file;
pub mod gather;
mod handler;
mod proxy;
mod pty;
mod session;

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
#[allow(unused)]
const WS_MSG_TYPE_PTY_READY: &str = "PtyReady";
const WS_MSG_TYPE_PTY_OUTPUT: &str = "PtyOutput";
