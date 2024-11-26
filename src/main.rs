mod common;
mod executor;
mod network;
mod ontime;
mod tssh;

use crate::common::{daemonizer::daemonize, evbus::EventBus, logger, option::EnumCommands, Opts};
use crate::network::AGENT_VERSION;

use std::env::{current_exe, set_current_dir};
use std::sync::{atomic::AtomicU64, Arc, LazyLock};
use std::{path::PathBuf, process::exit};

use log::{error, info};
use network::register;

static EXE_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| current_exe().unwrap().parent().unwrap().to_owned());

fn main() {
    set_work_dir();
    logger::init();
    info!("tat_agent start:[{}]", AGENT_VERSION);
    check_args();

    daemonize(move || {
        set_panic_handler();
        //check register info
        network::check();

        let eventbus = Arc::new(EventBus::new());
        let stop_counter = Arc::new(AtomicU64::new(0));

        executor::run(&eventbus, &stop_counter);
        ontime::run(&eventbus, &stop_counter);
        tssh::run(&eventbus, &stop_counter);
        network::ws::run(&eventbus);
    });
}

fn set_work_dir() {
    set_current_dir(&*EXE_DIR).expect("set cwd failed");
}

fn check_args() {
    if let Some(EnumCommands::Register { region, id, value }) = Opts::get_opts().command.as_ref() {
        match register(region, id, value) {
            Ok(_) => {
                println!("register success");
                exit(0)
            }
            Err(err) => {
                println!("register failed: {:#}", err);
                exit(-1)
            }
        }
    }
}

fn set_panic_handler() {
    std::panic::set_hook(Box::new(|pi| {
        error!("panic {}", pi.to_string());
        exit(-1);
    }));
}
