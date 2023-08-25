use std::sync::{Arc, OnceLock};

use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Opts {
    /// Work as pty server (for debug)
    #[clap(short, long)]
    pub server_mode: bool,

    /// Use console as log appender
    #[clap(short, long)]
    pub console_log: bool,

    /// Do not daemonize
    #[cfg(unix)]
    #[clap(short, long)]
    pub no_daemon: bool,

    #[command(subcommand)]
    pub command: Option<EnumCommands>,
}

#[derive(Subcommand, Debug)]
pub enum EnumCommands {
    /// Register machine to TAT server
    Register {
        /// The region to register
        region: String,

        /// `register_code_id` from `CreateRegisterCode()` API
        id: String,

        /// `register_code_value` from `CreateRegisterCode()` API
        value: String,
    },
}

impl Opts {
    pub fn get_opts() -> Arc<Opts> {
        static INS: OnceLock<Arc<Opts>> = OnceLock::new();
        let ins = INS.get_or_init(|| Arc::new(Opts::parse()));
        ins.clone()
    }
}
