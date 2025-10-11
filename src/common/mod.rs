pub mod config;
pub mod daemonizer;
pub mod evbus;
pub mod logger;
pub mod option;
pub mod sysinfo;

pub use option::Opts;

use std::path::Path;
use std::str::from_utf8;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::Result;
use rand::{distributions::Alphanumeric, thread_rng, Rng};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::{pkcs8::LineEnding, RsaPrivateKey, RsaPublicKey};
use tokio::fs::{create_dir_all, File};
use tokio::sync::oneshot::{self, Receiver, Sender};
use tokio::sync::{Mutex, Notify};
use tokio::time::sleep;

pub struct Stopper(Mutex<Option<Sender<()>>>, Mutex<Option<Receiver<()>>>);

impl Stopper {
    pub fn new() -> Self {
        let (tx, rx) = oneshot::channel();
        Self(Mutex::new(Some(tx)), Mutex::new(Some(rx)))
    }

    pub async fn stop(&self) {
        self.0.lock().await.take();
    }

    pub async fn get_receiver(&self) -> Option<Receiver<()>> {
        self.1.lock().await.take()
    }
}

pub struct Timer {
    interval: Duration,
    refresher: Notify,
    freeze_count: AtomicUsize,
}

impl Timer {
    pub fn new(interval: Duration) -> Self {
        Self {
            interval,
            refresher: Notify::new(),
            freeze_count: AtomicUsize::new(0),
        }
    }

    pub fn freeze(&self) {
        self.freeze_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn unfreeze(&self) {
        self.refresh();
        self.freeze_count.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn refresh(&self) {
        self.refresher.notify_one();
    }

    pub async fn timeout(&self) {
        loop {
            tokio::select! {
                _ = self.refresher.notified() => {}, // Continue loop, recreate sleep future
                _ = sleep(self.interval) => if self.freeze_count.load(Ordering::Relaxed) == 0 {
                    break;
                },
            }
        }
    }
}

pub fn generate_rsa_key() -> Option<(String, String)> {
    let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).ok()?;
    let public_key = RsaPublicKey::from(&private_key);

    let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).ok()?.to_string();
    let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).ok()?.to_string();
    Some((public_pem, private_pem))
}

pub fn gen_rand_str_with(len: usize) -> String {
    thread_rng()
        .sample_iter(&Alphanumeric)
        .take(len)
        .map(char::from)
        .collect()
}

#[cfg(windows)]
pub unsafe fn wsz2string(ptr: *const u16) -> String {
    use std::{ffi::OsString, os::windows::ffi::OsStringExt};
    let len = (0..isize::MAX).position(|i| *ptr.offset(i) == 0).unwrap();
    let slice = std::slice::from_raw_parts(ptr, len);
    OsString::from_wide(slice).to_string_lossy().into_owned()
}

#[cfg(windows)]
pub fn str2wsz(s: &str) -> Vec<u16> {
    use std::{ffi::OsStr, os::windows::ffi::OsStrExt};
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

pub fn get_now_secs() -> u64 {
    UNIX_EPOCH.elapsed().expect("get_now_secs failed").as_secs()
}

#[cfg(windows)]
pub fn get_current_username() -> String {
    use winapi::shared::minwindef::{DWORD, LPDWORD};
    use winapi::um::{winbase::GetUserNameW, winnt::LPWSTR};
    unsafe {
        let mut len: DWORD = 256;
        let mut username: Vec<u16> = vec![0; len as usize];

        GetUserNameW(username.as_ptr() as LPWSTR, &raw mut len as LPDWORD);
        username.set_len(len as usize);

        wsz2string(username.as_ptr())
    }
}

#[cfg(unix)]
pub fn get_current_username() -> String {
    let name = uzers::get_current_username().expect("get_current_username failed");
    String::from(name.to_str().expect("get_current_username failed"))
}

#[cfg(windows)]
pub fn cbs_exist() -> bool {
    use winapi::shared::{minwindef::FALSE, ntdef::NULL};
    use winapi::um::{handleapi::CloseHandle, synchapi::OpenEventW, winnt::SYNCHRONIZE};

    let handle = unsafe {
        OpenEventW(
            SYNCHRONIZE,
            FALSE,
            str2wsz("Global\\CBSVSS-WAIT-MODE").as_ptr(),
        )
    };
    if handle == NULL {
        return false;
    }
    unsafe { CloseHandle(handle) };
    true
}

#[cfg(unix)]
pub fn cbs_exist() -> bool {
    false
}

#[cfg(unix)]
pub fn update_file_permission(path: &str) {
    use std::ffi::c_char;
    use std::fs::{set_permissions, Permissions};
    use std::os::unix::fs::PermissionsExt;

    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    unsafe { libc::chown(path.as_ptr() as *const c_char, uid, gid) };
    let _ = set_permissions(path, Permissions::from_mode(0o600));
}

#[cfg(windows)]
pub fn update_file_permission(file_path: &str) {
    use std::process::Command;
    let _ = Command::new("icacls")
        .arg(file_path)
        .arg("/grant:r")
        .arg("Administrators:(F)")
        .arg("/inheritance:r")
        .output();
}

pub async fn create_file_with_parents(path: impl AsRef<Path>) -> Result<File> {
    let parent = path.as_ref().parent().unwrap();
    create_dir_all(parent).await?;
    Ok(File::create(path).await?)
}

#[cfg(unix)]
// recursively set permissions from start to end ancestor
pub async fn set_permissions_recursively(
    start: impl AsRef<Path>,
    end: Option<impl AsRef<Path>>,
    perm: std::fs::Permissions,
) -> Result<()> {
    let end = end.as_ref().map(AsRef::as_ref);
    for p in start.as_ref().ancestors() {
        tokio::fs::set_permissions(p, perm.clone()).await?;
        if Some(p) == end {
            break;
        }
    }
    Ok(())
}

// Checks a byte buffer for potential UTF-8 character truncation at the end.
pub fn incomplete_utf8_bytes(buffer: &[u8]) -> usize {
    buffer[buffer.len().saturating_sub(4)..]
        .utf8_chunks()
        .last()
        .map(|c| c.invalid())
        .filter(is_truncate_utf8)
        .map_or(0, <[u8]>::len)
}

fn is_truncate_utf8(invalid: &&[u8]) -> bool {
    !invalid.is_empty()
        // Safety: invalid is known to be invalid UTF-8, so from_utf8 will error.
        && unsafe { from_utf8(invalid).unwrap_err_unchecked() }
            .error_len()
            .is_none()
}
