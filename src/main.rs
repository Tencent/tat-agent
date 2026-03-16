mod common;
mod executor;
mod network;
mod ontime;
mod tssh;

use crate::common::option::{check_execute_args, check_register_args, check_unregister_args};
use crate::common::sysinfo::parallelism;
use crate::common::{daemonizer::daemonize, logger};
use crate::network::AGENT_VERSION;

use std::env::{current_exe, set_current_dir};
use std::sync::LazyLock;
use std::{path::PathBuf, process::exit};

use log::{error, info};
use tokio::runtime::Builder;

static EXE_DIR: LazyLock<PathBuf> =
    LazyLock::new(|| current_exe().unwrap().parent().unwrap().to_owned());

fn main() {
    set_work_dir();
    logger::init();
    info!("tat_agent start:[{}]", AGENT_VERSION);
    check_register_args();
    check_unregister_args();
    check_execute_args();

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

fn set_panic_handler() {
    std::panic::set_hook(Box::new(|pi| {
        error!("panic {}", pi);
        exit(-1);
    }));
}
