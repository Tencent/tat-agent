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

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        pub const TASK_STORE_PATH: &str = "/tmp/tat_agent/commands/";
        pub const TASK_LOG_PATH: &str = "/tmp/tat_agent/logs/";
        pub const FILE_EXECUTE_PERMISSION_MODE: u32 = 0o755;
    } else if #[cfg(windows)] {
        pub const TASK_STORE_PATH: &str = "C:\\Program Files\\qcloud\\tat_agent\\tmp\\commands\\";
        pub const TASK_LOG_PATH: &str = "C:\\Program Files\\qcloud\\tat_agent\\tmp\\logs\\";
    }
}
