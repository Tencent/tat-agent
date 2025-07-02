mod common;
mod executor;
mod network;
mod ontime;
mod tssh;

use crate::common::{daemonizer::daemonize, logger, Opts};
use crate::common::{option::EnumCommands::Register, sysinfo::parallelism};
use crate::network::AGENT_VERSION;

use std::env::{current_exe, set_current_dir};
use std::sync::{atomic::AtomicU64, LazyLock};
use std::{path::PathBuf, process::exit};

use log::{error, info};
use network::register;
use tokio::runtime::Builder;

static EXE_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| current_exe().unwrap().parent().unwrap().to_owned());

static STOP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn main() {
    set_work_dir();
    logger::init();
    info!("tat_agent start:[{}]", AGENT_VERSION);
    check_register_args();

    daemonize(move || {
        set_panic_handler();
        Builder::new_multi_thread()
            .worker_threads(parallelism())
            .enable_all()
            .build()
            .expect("tokio runtime build failed")
            .block_on(async move {
                //check register info
                network::check_register_info().await;

                executor::run().await;
                tssh::run().await;
                ontime::run().await;
                network::ws::run().await;
            });
    });
}

fn set_work_dir() {
    set_current_dir(&*EXE_DIR).expect("set_current_dir failed");
}

fn check_register_args() {
    let Some(Register { region, id, value }) = Opts::get_opts().command.as_ref() else {
        return;
    };
    if let Err(err) = register(region, id, value) {
        println!("register failed: {:#}", err);
        exit(-1)
    }
    println!("register success");
    exit(0)
}

fn set_panic_handler() {
    std::panic::set_hook(Box::new(|pi| {
        error!("panic {}", pi.to_string());
        exit(-1);
    }));
}
