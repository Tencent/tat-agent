mod common;
mod conpty;
mod daemonizer;
mod executor;
mod network;
mod ontime;
mod sysinfo;
use crate::common::consts::AGENT_VERSION;
use crate::common::evbus::EventBus;
use crate::common::logger;
use crate::common::option::EnumCommands;
use crate::common::Opts;
use log::{error, info};
use network::register;
use std::env;
use std::process::exit;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

fn main() {
    init_agent();
    check_args();

    daemonizer::daemonize(move || {
        set_panic_handler();
        //check register info
        network::check();

        let eventbus = Arc::new(EventBus::new());
        let stop_counter = Arc::new(AtomicU64::new(0));
        
        executor::thread::run(&eventbus, &stop_counter);
        ontime::thread::run(&eventbus, &stop_counter);
        conpty::gather::run(&eventbus, &stop_counter);
        network::ws::run(&eventbus);
    });
}

fn init_agent() {
    let current_bin = env::current_exe().expect("current path fail");
    let current_path = current_bin.parent().expect("parent path fail");
    env::set_current_dir(current_path).expect("set dir fail");
    logger::init();
    info!("agent initialized,version:[{}]", AGENT_VERSION);
}

fn check_args() {
    if let Some(commands) = Opts::get_opts().command.as_ref() {
        match commands {
            EnumCommands::Register(opt) => {
                match register(&opt.region, &opt.register_code_id, &opt.register_code_value) {
                    Ok(_) => {
                        print!("register success");
                        exit(0)
                    }
                    Err(err) => {
                        print!("register failed {}", err);
                        exit(-1)
                    }
                }
            }
        }
    }
}

fn set_panic_handler() {
    std::panic::set_hook(Box::new(|pi| {
        error!("panic {}", pi.to_string());
        std::process::exit(-1);
    }));
}
