use log::debug;
use log::info;
use std::path::PathBuf;
use daemonize::Daemonize;
use daemonize::DaemonizeError;

use crate::common::consts::{AGENT_DEFAULT_WORK_DIRECTORY, PID_FILE};

pub fn daemonize(entry: fn()) {
    let agent_dir = get_agent_dir();
    let daemonize = Daemonize::new()
        // set working dir of the daemon to where agent program is
        .working_directory(agent_dir)
        .pid_file(PID_FILE);
    match daemonize.start() {
        Ok(_) => info!("daemonize succ"),
        Err(e) => {
            let mut reason = format!("Daemonize failed because: {}.", e);
            if let DaemonizeError::LockPidfile(_errno) = e {
                reason.push_str(" Another daemon agent may be already running.");
            }
            panic!("{}", reason);
        }
    };
    entry();
}

fn get_agent_dir() -> PathBuf {
    let mut dir = std::env::current_exe().unwrap();
    debug!("agent path:{:?}", dir);
    if dir.pop() {
        debug!("agent dir:{:?}", dir);
        dir
    } else {
        PathBuf::from(AGENT_DEFAULT_WORK_DIRECTORY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::logger;

    #[test]
    fn test_get_agent_dir() {
        logger::init_test_log();
        get_agent_dir();
    }
}
