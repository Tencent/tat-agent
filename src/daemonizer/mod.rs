cfg_if::cfg_if! {
    if #[cfg(unix)] {
        mod unix;
        pub use unix::daemonize;
    } else if #[cfg(windows)] {
        mod windows;
        pub use windows::daemonize;
        pub use windows::wow64_disable_exc;
    } else {
        // not supported platform.
        use log::warn;
        pub fn daemonize(entry: fn()) {
            warn!("unsupported platform, daemonize will do nothing.")
            entry();
        }
    }
}
