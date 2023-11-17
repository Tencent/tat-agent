pub mod proc;
mod store;
pub mod thread;
#[cfg(unix)]
pub mod unix;
#[cfg(windows)]
pub mod windows;

pub const FINISH_RESULT_TERMINATED: &str = "TERMINATED";
pub const CMD_TYPE_BAT: &str = "BAT";
pub const CMD_TYPE_SHELL: &str = "SHELL";
pub const CMD_TYPE_POWERSHELL: &str = "POWERSHELL";
#[cfg(unix)]
pub const FILE_EXECUTE_PERMISSION_MODE: u32 = 0o751;


