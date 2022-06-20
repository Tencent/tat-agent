use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::{OsStrExt, OsStringExt};

pub fn wsz2string(ptr: *const u16) -> String {
    unsafe {
        let len = (0..isize::MAX).position(|i| *ptr.offset(i) == 0).unwrap();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

pub fn str2wsz(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect::<Vec<_>>()
}
