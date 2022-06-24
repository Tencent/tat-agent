use std::env;
// agent
pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

//event bus slots
pub const EVENT_SLOT_DEFAULT: &str = "event_slot_default";
pub const EVENT_SLOT_PTY_CMD: &str = "event_slot_pty_cmd";

// log related
pub const LOG_PATTERN: &str = "{d}|{f}:{L}|{l}|{m}{n}";
pub const LOG_FILE_NAME: &str = "log/tat_agent.log";
pub const LOG_FILE_NAME_WHEN_ROLL: &str = "log/tat_agent_{}.log";
pub const LOG_FILE_SIZE: u64 = 10 * 1024 * 1024;
pub const LOG_FILE_BASE_INDEX: u32 = 0;
pub const MAX_LOG_FILE_COUNT: u32 = 2;
pub const LOG_LEVEL: log::LevelFilter = log::LevelFilter::Info;
pub const LOG_LEVEL_DEBUG: log::LevelFilter = log::LevelFilter::Debug;

// http headers used for e2e test.
pub const VPCID_HEADER: &str = "Tat-Vpcid";
pub const VIP_HEADER: &str = "Tat-Vip";

pub const SELF_UPDATE_FILENAME: &str = "agent_update.zip";
cfg_if::cfg_if! {
    if #[cfg(unix)] {
        //bash block related
        pub const BASH_PREEXC:&str="/usr/local/qcloud/bash-precmd/bash-preexec.sh";
        pub const BLOCK_INIT:&str="/usr/local/qcloud/bash-precmd/bash-init.sh";
        pub const COREOS_BASH_PREEXC:&str="/var/lib/qcloud/bash-precmd/bash-preexec.sh";
        pub const COREOS_BLOCK_INIT:&str="/var/lib/qcloud/bash-precmd/bash-init.sh";
        // daemon related
        pub const PID_FILE: &str = "/var/run/tat_agent.pid";
        pub const TASK_STORE_PATH: &str = "/tmp/tat_agent/commands/";
        pub const TASK_LOG_PATH: &str = "/tmp/tat_agent/logs/";
        pub const SELF_UPDATE_PATH: &str = "/tmp/tat_agent/self_update/";
        pub const SELF_UPDATE_SCRIPT: &str = "self_update.sh";
        pub const INSTALL_SCRIPT: &str = "install.sh";
        pub const FILE_EXECUTE_PERMISSION_MODE: u32 = 0o755;
        pub const PIPE_BUF_DEFAULT_SIZE: usize = 64 * 4096;
    } else if #[cfg(windows)] {
        pub const TASK_STORE_PATH: &str = "C:\\Program Files\\qcloud\\tat_agent\\tmp\\commands\\";
        pub const TASK_LOG_PATH: &str = "C:\\Program Files\\qcloud\\tat_agent\\tmp\\logs\\";
        pub const SELF_UPDATE_PATH: &str = "C:\\Program Files\\qcloud\\tat_agent\\tmp\\self_update\\";
        pub const SELF_UPDATE_SCRIPT: &str = "self_update.bat";
    }
}

// ws related
pub const WS_VERSION_HEADER: &str = "Tat-Version";
pub const WS_KERNEL_NAME_HEADER: &str = "Tat-KernelName";
pub const WS_PASSIVE_CLOSE: &str = "cli_passive_close";
pub const WS_PASSIVE_CLOSE_CODE: u16 = 3001;
pub const WS_ACTIVE_CLOSE: &str = "cli_active_close";
pub const WS_ACTIVE_CLOSE_CODE: u16 = 3002;
pub const MAX_PING_FROM_LAST_PONG: usize = 3;
pub const WS_RECONNECT_INTERVAL: u64 = 3;
// ws msg
pub const WS_MSG_TYPE_KICK: &str = "kick";
pub const WS_MSG_TYPE_ACK: &str = "ack";

pub const WS_MSG_TYPE_CHECK_UPDATE: &str = "CheckUpdate";

pub const WS_MSG_TYPE_PTY_START: &str = "PtyStart";
pub const WS_MSG_TYPE_PTY_STOP: &str = "PtyStop";
pub const WS_MSG_TYPE_PTY_RESIZE: &str = "PtyResize";
pub const WS_MSG_TYPE_PTY_INPUT: &str = "PtyInput";

pub const WS_MSG_TYPE_PTY_READY: &str = "PtyReady";
pub const WS_MSG_TYPE_PTY_ERROR: &str = "PtyError";
pub const WS_MSG_TYPE_PTY_OUTPUT: &str = "PtyOutput";

pub const PTY_WS_MSG: &str = "pty_ws_msg";
pub const PTY_REMOVE_INTERVAL: u64 = 10 * 60;

// http related
pub const HTTP_REQUEST_TIME_OUT: u64 = 5;
pub const HTTP_REQUEST_RETRIES: u64 = 3;
pub const HTTP_REQUEST_NO_RETRIES: u64 = 1;
pub const HTTP_REQUEST_RETRY_INTERVAL: u64 = 5;

pub const TASK_STORE_PREFIX: &str = "task";
pub const FINISH_RESULT_TIMEOUT: &str = "TIMEOUT";
pub const FINISH_RESULT_SUCCESS: &str = "SUCCESS";
pub const FINISH_RESULT_FAILED: &str = "FAILED";
pub const FINISH_RESULT_START_FAILED: &str = "START_FAILED";
pub const FINISH_RESULT_TERMINATED: &str = "TERMINATED";

// task start failed errInfo
#[macro_export]
macro_rules! start_failed_err_info {
    (ERR_WORKING_DIRECTORY_NOT_EXISTS, $working_directory:expr) => {
        format!("DirectoryNotExists: working_directory `{}` not exists", $working_directory)
    };
    (ERR_USER_NOT_EXISTS, $user:expr) => {
        format!("UserNotExists: user `{}` not exists", $user)
    };
    (ERR_USER_NO_PERMISSION_OF_WORKING_DIRECTORY, $user:expr, $working_directory:expr) => {
        format!("DirectoryPermissionDeny: user `{}` has no permission of working_directory `{}`",
            $user, $working_directory)
    };
    (ERR_SUDO_NOT_EXISTS) => {
        format!("SudoNotExists: command sudo not exists")
    };
    (ERR_SCRIPT_FILE_STORE_FAILED, $store_path:expr) => {
        format!("ScriptStoreFailed: script file store failed at `{}`, please check disk space or permission",
            $store_path)
    };
    (ERR_LOG_FILE_STORE_FAILED, $store_path:expr) => {
        format!("LogStoreFailed: log file store failed at `{}`, please check disk space or permission",
            $store_path)
    };
}

// cmd related
pub const CMD_TYPE_SHELL: &str = "SHELL";
pub const CMD_TYPE_POWERSHELL: &str = "POWERSHELL";
pub const CMD_TYPE_BAT: &str = "BAT";

pub const SUFFIX_SHELL: &str = ".sh";
pub const SUFFIX_BAT: &str = ".bat";
pub const SUFFIX_PS1: &str = ".ps1";

pub const OUTPUT_BYTE_LIMIT_EACH_REPORT: usize = 30 * 1024;
pub const DEFAULT_OUTPUT_BYTE: u64 = 24 * 1024;

// ontime related
pub const ONTIME_KICK_SOURCE: &str = "ONTIME_KICK";
pub const ONTIME_KICK_INTERVAL: u64 = 3600 * 24;
pub const ONTIME_PING_INTERVAL: u64 = 2 * 60;
pub const ONTIME_UPDATE_INTERVAL: u64 = 2 * 60 * 60;
pub const ONTIME_THREAD_INTERVAL: u64 = 1;
pub const ONTIME_CHECK_TASK_NUM: u64 = 10;

// self update related
pub const UPDATE_FILE_UNZIP_DIR: &str = "agent_update_unzip";
pub const AGENT_FILENAME: &str = "tat_agent";
pub const UPDATE_DOWNLOAD_TIMEOUT: u64 = 20 * 60;

pub const WS_URL_DEBUG: &str = "ws://proxy:8086/ws";
pub const WS_URLS: [&'static str; 4] = [
    "ws://notify.tat-tc.tencent.cn:8086/ws",
    "ws://notify.tat-tc.tencent.com.cn:8086/ws",
    "ws://notify.tat-tc.tencentyun.com:8086/ws",
    "ws://notify.tat.tencent-cloud.com:8086/ws",
];

pub const INVOKE_API_DEBUG: &str = "http://proxy-invoke";
pub const INVOKE_APIS: [&'static str; 4] = [
    "https://invoke.tat-tc.tencent.cn",
    "https://invoke.tat-tc.tencent.com.cn",
    "https://invoke.tat-tc.tencentyun.com",
    "https://invoke.tat.tencent-cloud.com",
];

pub const METADATA_API_DEBUG: &str = "http://mock-server:8000";
pub const METADATA_API: &str = "http://metadata.tencentyun.com";

//pty_flags
pub const PTY_FLAG_INIT_BLOCK: u32 = 0x00000001;

#[cfg(test)]
mod tests {
    #[test]
    fn test_err_info() {
        let dir = "/tmp/";
        let user = "worker";
        let s = start_failed_err_info!(ERR_WORKING_DIRECTORY_NOT_EXISTS, dir);
        assert_err_info(&s, "DirectoryNotExists");

        let s = start_failed_err_info!(ERR_USER_NOT_EXISTS, user);
        assert_err_info(&s, "UserNotExists");

        let s = start_failed_err_info!(ERR_USER_NO_PERMISSION_OF_WORKING_DIRECTORY, user, dir);
        assert_err_info(&s, "DirectoryPermissionDeny");

        let s = start_failed_err_info!(ERR_SUDO_NOT_EXISTS);
        assert_err_info(&s, "SudoNotExists");

        let s = start_failed_err_info!(ERR_SCRIPT_FILE_STORE_FAILED, dir);
        assert_err_info(&s, "ScriptStoreFailed");
    }

    fn assert_err_info(err_info: &String, err_code: &str) {
        println!("err_code: {}, err_info: {}", err_code, err_info);
        let s = format!("{}{}", err_code, ":");
        assert!(err_info.starts_with(s.as_str()));
    }
}
