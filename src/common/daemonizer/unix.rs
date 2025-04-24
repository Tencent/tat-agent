use crate::common::Opts;

use daemonize::Daemonize;
use log::info;

const PID_FILE: &str = "/var/run/tat_agent.pid";

pub fn daemonize(entry: fn()) {
    if Opts::get_opts().no_daemon {
        entry();
        return;
    };

    let umask = unsafe {
        let current_umask = libc::umask(0);
        libc::umask(current_umask); // Restore the original umask
        current_umask
    };
    let daemonize = Daemonize::new()
        .pid_file(PID_FILE)
        .working_directory(".")
        .umask(umask);
    match daemonize.start() {
        Ok(_) => info!("daemonize success"),
        Err(e) => {
            let mut reason = format!("Daemonize failed because: {}.", e);
            if reason.contains("unable to lock pid file") {
                reason.push_str(" Another daemon agent may be already running.");
            }
            panic!("{}", reason);
        }
    };
    entry();
}
