mod common;
mod conpty;
mod cos;
mod daemonizer;
mod executor;
mod http;
mod ontime;
mod types;
mod uname;
mod ws;

use crate::common::consts::AGENT_VERSION;
use crate::common::evbus::EventBus;
use crate::common::logger;
use crate::common::Opts;
use crate::ontime::timer::Timer;
use chrono::Local;
use log::info;
use std::env;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

#[tokio::main]
async fn main() {
    let _opts = Opts::get_opts();
    set_work_dir();
    set_panic_handler();
    logger::init();
    info!("agent start,version:[{}]", AGENT_VERSION);
    Timer::get_instance();

    daemonizer::daemonize(move || {
        let eventbus = Arc::new(EventBus::new());
        let running_task_num = Arc::new(AtomicU64::new(0));

        http::thread::run(&eventbus, &running_task_num);
        ontime::thread::run(&eventbus, &running_task_num);
        conpty::thread::run(&eventbus, &running_task_num);
        ws::thread::run(&eventbus);
    });
}

fn set_work_dir() {
    let exe_path = env::current_exe().unwrap();
    let work_dir = exe_path.parent().unwrap();
    env::set_current_dir(work_dir).unwrap();
}

fn set_panic_handler() {
    std::panic::set_hook(Box::new(|pi| {
        let date = Local::now();
        let pi_str = format!("{} {}", date.format("[%Y-%m-%d %H:%M:%S]"), &pi.to_string());
        let _ = std::fs::write("log/panic.log", pi_str.as_bytes());
    }));
}
