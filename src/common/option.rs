use std::sync::Arc;

use clap::{Args, Parser, Subcommand};
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Opts {
    ///Work as pty server (for debug）
    #[clap(short, long)]
    pub server_mode: bool,

    ///Use console as log appender
    #[clap(short, long)]
    pub console_log: bool,

    ///Do not daemonize
    #[cfg(unix)]
    #[clap(short, long)]
    pub no_daemon: bool,

    #[command(subcommand)]
    pub command: Option<EnumCommands>,
}

#[derive(Subcommand, Debug)]
pub enum EnumCommands {
    Register(RegisterOpt),
}

#[derive(Args, Debug,Clone)]
pub struct RegisterOpt {
    #[clap(long)]
    pub region: String,
    #[clap(long)]
    pub register_code_id: String,
    #[clap(long)]
    pub register_code_value: String,
}

impl Opts {
    pub fn get_opts() -> Arc<Opts> {
        static mut INS: Option<Arc<Opts>> = None;
        let &mut ins;
        unsafe {
            ins = INS.get_or_insert_with(|| Arc::new(Opts::parse()));
        }
        ins.clone()
    }
}
