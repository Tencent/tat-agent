use crate::common::Opts;

use log::{debug, info, Record};
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::filter::{Filter, Response};

const LOG_PATTERN: &str = "{d}|{f}:{L}|{l}|{m}{n}";
const LOG_FILE_NAME: &str = "log/tat_agent.log";
const LOG_FILE_NAME_WHEN_ROLL: &str = "log/tat_agent_{}.log";
const LOG_FILE_SIZE: u64 = 1 * 1024 * 1024;
const LOG_FILE_BASE_INDEX: u32 = 0;
const MAX_LOG_FILE_COUNT: u32 = 2;
const LOG_LEVEL: log::LevelFilter = log::LevelFilter::Info;
const LOG_LEVEL_DEBUG: log::LevelFilter = log::LevelFilter::Debug;

pub fn init() {
    let log_level = LOG_LEVEL;
    let trigger = SizeTrigger::new(LOG_FILE_SIZE);
    let roller = FixedWindowRoller::builder()
        .base(LOG_FILE_BASE_INDEX)
        .build(LOG_FILE_NAME_WHEN_ROLL, MAX_LOG_FILE_COUNT)
        .expect("FixedWindowRoller build failed");
    let policy = CompoundPolicy::new(Box::new(trigger), Box::new(roller));
    let logfile = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
        .build(LOG_FILE_NAME, Box::new(policy))
        .expect("RollingFileAppender build failed");

    let stdout = ConsoleAppender::builder().target(Target::Stdout).build();

    let appender = if Opts::get_opts().console_log {
        Appender::builder()
            .filter(Box::new(ThresholdFilter::new(log_level)))
            .build("logger", Box::new(stdout))
    } else {
        Appender::builder()
            .filter(Box::new(SnapshortFilter))
            .filter(Box::new(ThresholdFilter::new(log_level)))
            .build("logger", Box::new(logfile))
    };

    let config = Config::builder()
        .appender(appender)
        .build(Root::builder().appender("logger").build(log_level))
        .expect("Config build failed");

    let config_log = format!("{:?}", config);
    log4rs::init_config(config).unwrap();
    debug!("logger init success, config: {}", config_log);
}

#[derive(Debug)]
pub struct SnapshortFilter;

impl Filter for SnapshortFilter {
    #[cfg(unix)]
    fn filter(&self, _: &Record) -> Response {
        Response::Neutral
    }

    #[cfg(windows)]
    fn filter(&self, _: &Record) -> Response {
        use crate::common::utils::str2wsz;
        use winapi::shared::minwindef::FALSE;
        use winapi::shared::ntdef::NULL;
        use winapi::um::handleapi::CloseHandle;
        use winapi::um::synchapi::OpenEventW;
        use winapi::um::winnt::SYNCHRONIZE;

        let handle = unsafe {
            OpenEventW(
                SYNCHRONIZE,
                FALSE,
                str2wsz("Global\\CBSVSS-WAIT-MODE").as_ptr(),
            )
        };
        if handle != NULL {
            unsafe { CloseHandle(handle) };
            Response::Reject
        } else {
            Response::Neutral
        }
    }
}

#[allow(dead_code)]
pub fn init_test_log() {
    let stdout: ConsoleAppender = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
        .build();
    let log_config = log4rs::config::Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LOG_LEVEL_DEBUG))
        .unwrap();
    match log4rs::init_config(log_config) {
        Ok(_) => (),
        Err(why) => info!("init test log failed: {}", why),
    };
    info!("logger init succ");
}
