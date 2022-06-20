use std::sync::Arc;

use clap::Parser;
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
pub struct Opts {
    ///Work as pty server (for debug） 
    #[clap(short, long)]
    pub pty_server: bool,

    ///Use console as log appender
    #[clap(short, long)]
    pub console_log: bool,

    ///Set log level as debug
    #[clap(short, long)]
    pub debug_log: bool,

    ///Do not daemonize
    #[cfg(unix)]
    #[clap(short, long)]
    pub no_daemon: bool,
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
