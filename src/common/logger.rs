use crate::common::{update_file_permission, Opts};

use std::fs::{create_dir_all, OpenOptions};

use anyhow::Result;
use log::{debug, Record};
use log4rs::append::console::{ConsoleAppender, Target};
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::roll::Roll;
use log4rs::append::rolling_file::policy::compound::trigger;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::Policy;
use log4rs::append::rolling_file::{LogFile, RollingFileAppender};
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;
use log4rs::filter::{Filter, Response};

const LOG_PATTERN: &str = "{d}|{f}:{L}|{l}|{m}{n}";
const LOG_FILE_NAME: &str = "log/tat_agent.log";
const LOG_FILE_NAME_WHEN_ROLL: &str = "log/tat_agent_{}.log";
const LOG_FILE_SIZE: u64 = 10 * 1024 * 1024;
const LOG_FILE_BASE_INDEX: u32 = 0;
const MAX_LOG_FILE_COUNT: u32 = 2;
const LOG_LEVEL: log::LevelFilter = log::LevelFilter::Info;

pub fn init() {
    let log_level = LOG_LEVEL;
    let appender = if Opts::get_opts().console_log {
        let stdout = ConsoleAppender::builder().target(Target::Stdout).build();
        Appender::builder()
            .filter(Box::new(ThresholdFilter::new(log_level)))
            .build("logger", Box::new(stdout))
    } else {
        //create the file now to ensure that the permissions can be set successfully
        let _ = create_dir_all("log");
        let _ = OpenOptions::new()
            .create(true)
            .append(true)
            .open(LOG_FILE_NAME);

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
    update_file_permission(LOG_FILE_NAME)
}

#[derive(Debug)]
pub struct SnapshortFilter;

impl Filter for SnapshortFilter {
    fn filter(&self, _: &Record) -> Response {
        use super::cbs_exist;
        if cbs_exist() {
            Response::Reject
        } else {
            Response::Neutral
        }
    }
}

#[derive(Debug)]
pub struct CompoundPolicy {
    trigger: Box<dyn trigger::Trigger>,
    roller: Box<dyn Roll>,
}

impl CompoundPolicy {
    /// Creates a new `CompoundPolicy`.
    pub fn new(trigger: Box<dyn trigger::Trigger>, roller: Box<dyn Roll>) -> CompoundPolicy {
        CompoundPolicy { trigger, roller }
    }
}

impl Policy for CompoundPolicy {
    fn process(&self, log: &mut LogFile) -> Result<()> {
        if self.trigger.trigger(log)? {
            log.roll();
            self.roller.roll(log.path())?;
            let _ = OpenOptions::new()
                .create(true)
                .append(true)
                .open(LOG_FILE_NAME);
            update_file_permission(LOG_FILE_NAME)
        }
        Ok(())
    }

    fn is_pre_process(&self) -> bool {
        self.trigger.is_pre_process()
    }
}

#[cfg(test)]
pub fn init_test_log() {
    use log::info;
    const LOG_LEVEL_DEBUG: log::LevelFilter = log::LevelFilter::Debug;

    let stdout: ConsoleAppender = ConsoleAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
        .build();
    let log_config = log4rs::config::Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(LOG_LEVEL_DEBUG))
        .unwrap();
    let _ = log4rs::init_config(log_config);
    info!("logger init succ");
}
