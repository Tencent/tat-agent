use log::info;
use log::error;
use std::process::exit;


pub trait GracefulUnwrap<T> {
    fn unwrap_or_exit(self, desc: &str) -> T;
    fn or_log(self, desc: &str);
}

impl<T, E: std::fmt::Debug> GracefulUnwrap<T> for Result<T, E> {
    fn unwrap_or_exit(self, desc: &str) -> T {
        self.unwrap_or_else(|e| {
            error!("Result:{:#?}, Desc:{}, exit program now", e, desc);
            exit(1);
        })
    }

    fn or_log(self, desc: &str) {
        if let Err(e) = self {
            info!("Result:{:#?}, Desc:{}, program continue", e, desc);
        }
    }
}
