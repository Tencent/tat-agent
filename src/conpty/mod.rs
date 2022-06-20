use std::{fs::File, sync::Arc};
#[cfg(windows)]
mod bind;
pub mod thread;
#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

pub trait PtySystem {
    fn openpty(
        &self,
        user_name: &str,
        cols: u16,
        rows: u16,
        flag: u32,
    ) -> Result<Arc<dyn PtySession + Send + Sync>, String>;
}

pub trait PtySession {
    fn resize(&self, cols: u16, rows: u16) -> Result<(), String>;
    fn get_reader(&self) -> Result<File, String>;
    fn get_writer(&self) -> Result<File, String>;
}
