use daemonize::Daemonize;
use daemonize::DaemonizeError;
use log::info;

use crate::common::consts::PID_FILE;
use crate::common::Opts;

pub fn daemonize(entry: fn()) {
    if Opts::get_opts().no_daemon {
        entry();
        return;
    };
    let daemonize = Daemonize::new().pid_file(PID_FILE);
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
