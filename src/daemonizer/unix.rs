use crate::common::Opts;

use daemonize::Daemonize;
use log::info;

const PID_FILE: &str = "/var/run/tat_agent.pid";

pub fn daemonize(entry: fn()) {
    if Opts::get_opts().no_daemon {
        entry();
        return;
    };

    let daemonize = Daemonize::new().pid_file(PID_FILE).working_directory(".");
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
