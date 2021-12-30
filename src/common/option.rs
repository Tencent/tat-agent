use std::sync::Arc;

use clap::{App, Arg};

use crate::common::consts::AGENT_VERSION;

#[derive(Debug, Clone)]
pub struct Opts {
    debug: Option<bool>,
}

impl Opts {
    pub fn get_opts() -> Arc<Opts> {
        static mut INS: Option<Arc<Opts>> = None;
        let &mut ins;
        unsafe {
            ins = INS.get_or_insert_with(|| Arc::new(Self::generate_opts()));
        }
        ins.clone()
    }

    pub fn debug(&self) -> &Option<bool> {
        &self.debug
    }

    fn generate_opts() -> Self {
        let matches = App::new("tat_agent")
            .version(AGENT_VERSION)
            .arg(
                Arg::with_name("debug")
                    .long("debug")
                    .help("Set log level to debug")
                    .required(false),
            )
            .get_matches();

        let mut debug = None;
        if matches.is_present("debug") {
            debug = Some(true);
        }
        // return Opts
        Opts { debug }
    }
}
