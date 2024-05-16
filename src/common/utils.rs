#[cfg(windows)]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use rsa::pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey};
use rsa::pkcs8::LineEnding;
use rsa::{RsaPrivateKey, RsaPublicKey};
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::oneshot::{self, Receiver, Sender};
use tokio::time::{delay_until, Instant};

pub struct Stopper(Mutex<Option<Sender<()>>>, Mutex<Option<Receiver<()>>>);

impl Stopper {
    pub fn new() -> Self {
        let (tx, rx) = oneshot::channel();
        Self(Mutex::new(Some(tx)), Mutex::new(Some(rx)))
    }

    pub fn stop(&self) {
        self.0.lock().expect("lock failed").take();
    }

    pub fn get_receiver(&self) -> Option<Receiver<()>> {
        self.1.lock().expect("lock failed").take()
    }
}

pub struct Timer {
    last_time: Mutex<Instant>,
    interval: u64,
    freeze_count: AtomicUsize,
}

impl Timer {
    pub fn new(interval: u64) -> Self {
        Self {
            last_time: Mutex::new(Instant::now()),
            interval,
            freeze_count: AtomicUsize::new(0),
        }
    }

    pub fn freeze(&self) {
        self.freeze_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn unfreeze(&self) {
        self.refresh();
        self.freeze_count.fetch_sub(1, Ordering::SeqCst);
    }

    pub fn refresh(&self) {
        self.refresh_with(Instant::now());
    }

    pub async fn timeout(&self) {
        while !self.is_timeout() {
            delay_until(self.may_timeout_at()).await
        }
    }

    pub fn is_timeout_refresh(&self, inst: Instant) -> bool {
        if self.is_timeout_with(inst) {
            return true;
        }
        self.refresh_with(inst);
        false
    }

    fn refresh_with(&self, inst: Instant) {
        *self.last_time.lock().expect("lock failed") = inst;
    }

    fn is_timeout_with(&self, inst: Instant) -> bool {
        if self.freeze_count.load(Ordering::SeqCst) != 0 {
            self.refresh();
            return false;
        }
        inst.elapsed().as_secs() >= self.interval
    }

    fn is_timeout(&self) -> bool {
        self.is_timeout_with(self.last_time())
    }

    fn may_timeout_at(&self) -> Instant {
        self.last_time() + Duration::from_secs(self.interval)
    }

    fn last_time(&self) -> Instant {
        *self.last_time.lock().expect("lock failed")
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
pub fn wsz2string(ptr: *const u16) -> String {
    unsafe {
        let len = (0..isize::MAX).position(|i| *ptr.offset(i) == 0).unwrap();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

#[cfg(windows)]
pub fn str2wsz(s: &str) -> Vec<u16> {
    OsStr::new(s).encode_wide().chain(Some(0)).collect()
}

pub fn get_now_secs() -> u64 {
    UNIX_EPOCH.elapsed().expect("get_now_secs failed").as_secs()
}

#[cfg(windows)]
pub fn get_current_username() -> String {
    use winapi::{
        shared::minwindef::{DWORD, LPDWORD},
        um::{winbase::GetUserNameW, winnt::LPWSTR},
    };

    unsafe {
        let mut len: DWORD = 256;
        let mut user_name: Vec<u16> = Vec::new();
        user_name.resize(len as usize, 0);

        GetUserNameW(user_name.as_ptr() as LPWSTR, &mut len as LPDWORD);
        user_name.set_len(len as usize);

        let user_name = wsz2string(user_name.as_ptr());
        user_name
    }
}

#[cfg(unix)]
pub fn get_current_username() -> String {
    let name = users::get_current_username().expect("get_current_username failed");
    String::from(name.to_str().expect("get_current_username failed"))
}

#[cfg(windows)]
pub fn cbs_exist() -> bool {
    use winapi::{
        shared::{minwindef::FALSE, ntdef::NULL},
        um::{handleapi::CloseHandle, synchapi::OpenEventW, winnt::SYNCHRONIZE},
    };

    let handle = unsafe {
        OpenEventW(
            SYNCHRONIZE,
            FALSE,
            str2wsz("Global\\CBSVSS-WAIT-MODE").as_ptr(),
        )
    };
    if handle != NULL {
        unsafe { CloseHandle(handle) };
        true
    } else {
        false
    }
}

#[cfg(unix)]
pub fn cbs_exist() -> bool {
    false
}

#[cfg(unix)]
pub fn update_file_permission(path: &str) {
    use std::{
        ffi::c_char,
        fs::{self, Permissions},
        os::unix::fs::PermissionsExt,
    };
    let uid = unsafe { libc::getuid() };
    let gid = unsafe { libc::getgid() };

    unsafe { libc::chown(path.as_ptr() as *const c_char, uid, gid) };
    let _ = fs::set_permissions(path, Permissions::from_mode(0o600));
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
