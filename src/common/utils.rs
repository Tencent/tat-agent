#[cfg(windows)]
use std::ffi::{OsStr, OsString};
#[cfg(windows)]
use std::os::windows::ffi::{OsStrExt, OsStringExt};

use std::time::{SystemTime, UNIX_EPOCH};

use rsa::{
    pkcs1::{EncodeRsaPrivateKey, EncodeRsaPublicKey},
    pkcs8::LineEnding,
    RsaPrivateKey, RsaPublicKey,
};

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
    OsStr::new(s)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect::<Vec<_>>()
}

pub fn get_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("get_now_secs fail")
        .as_secs()
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
    let name = users::get_current_username().expect("get_current_username fail");
    String::from(name.to_str().expect("get_current_username fail"))
}

pub fn generate_rsa_key() -> Option<(String, String)> {
    let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048).ok()?;
    let public_key = RsaPublicKey::from(&private_key);

    let public_pem = public_key.to_pkcs1_pem(LineEnding::LF).ok()?.to_string();
    let private_pem = private_key.to_pkcs1_pem(LineEnding::LF).ok()?.to_string();
    Some((public_pem, private_pem))
}
