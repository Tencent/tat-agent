use clap::lazy_static::lazy_static;
use std::{fs::File, sync::Arc};
use tokio::runtime::Runtime;
mod ptybin;
pub mod thread;
cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
    } else if #[cfg(windows)] {
        mod windows;
        mod bind;
        mod parser;
    }
}

pub trait PtySystem {
    fn openpty(
        &self,
        user_name: &str,
        cols: u16,
        rows: u16,
        flag: u32,
    ) -> Result<Arc<dyn PtySession + Send + Sync>, String>;
}

type Handler = Box<dyn Fn() -> Result<Vec<u8>,String> + Sync + Send + 'static>;
pub trait PtySession {
    fn resize(&self, cols: u16, rows: u16) -> Result<(), String>;
    fn get_reader(&self) -> Result<File, String>;
    fn get_writer(&self) -> Result<File, String>;
    fn get_pid(&self) -> Result<u32, String>;
    fn work_as_user(&self, func: Handler) -> Result<Vec<u8>, String>;
    fn inspect_access(&self, path: &str, access: u8) -> Result<(), String>;
}

lazy_static! {
    static ref PTY_RUNTIME: Arc<Runtime> = Arc::new(Runtime::new().unwrap());
}
