use log::info;
use log4rs::append::rolling_file::policy::compound::roll::fixed_window::FixedWindowRoller;
use log4rs::append::rolling_file::policy::compound::trigger::size::SizeTrigger;
use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::RollingFileAppender;
use log4rs::config::Appender;
use log4rs::config::Config;
use log4rs::config::Root;
use log4rs::encode::pattern::PatternEncoder;
use log4rs::filter::threshold::ThresholdFilter;

use crate::common::consts::{
    LOG_FILE_BASE_INDEX, LOG_FILE_NAME, LOG_FILE_NAME_WHEN_ROLL, LOG_FILE_SIZE, LOG_LEVEL,
    LOG_LEVEL_DEBUG, LOG_PATTERN, MAX_LOG_FILE_COUNT,
};
use crate::common::Opts;

pub fn init() {
    let opts = Opts::get_opts();
    let option_log_level = opts.debug();
    let mut log_level: log::LevelFilter = LOG_LEVEL;

    let logfile = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(LOG_PATTERN)))
        .build(
            LOG_FILE_NAME,
            Box::new(CompoundPolicy::new(
                Box::new(SizeTrigger::new(LOG_FILE_SIZE)),
                Box::new(
                    FixedWindowRoller::builder()
                        .base(LOG_FILE_BASE_INDEX)
                        .build(LOG_FILE_NAME_WHEN_ROLL, MAX_LOG_FILE_COUNT)
                        .unwrap(),
                ),
            )),
        )
        .unwrap();
    if let Some(true) = option_log_level {
        log_level = LOG_LEVEL_DEBUG;
    }
    let config = Config::builder()
        .appender(
            Appender::builder()
                .filter(Box::new(ThresholdFilter::new(log_level)))
                .build("logfile", Box::new(logfile)),
        )
        .build(Root::builder().appender("logfile").build(log_level))
        .unwrap();
    let config_log = format!("{:?}", config);
    log4rs::init_config(config).unwrap();
    info!("logger init succ, config: {}", config_log);
}

#[allow(dead_code)]
pub fn init_test_log() {
    use log4rs::append::console::ConsoleAppender;

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
