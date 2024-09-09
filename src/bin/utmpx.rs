/*
The TAT agent can only be compiled as a static version using the musl library instead of the libc library.
However, since the musl library does not support utmpx-related functions, the only option is to separately
compile this file into a binary using static compilation with glibc.
*/

#[cfg(unix)]
mod unix {
    use libc::{c_char, c_short, exit};
    use libc::{time, utmpx};
    use std::env;
    use std::ffi::CString;
    use std::mem;
    use std::ptr;

    pub const USER_PROCESS: c_short = 7;
    pub const DEAD_PROCESS: c_short = 8;
    const _PATH_WTMP: &str = "/var/log/wtmp";

    extern "C" {
        fn updwtmp(wtmp_file: *const libc::c_char, ut: *const libc::utmpx);
        fn pututxline(ut: *const libc::utmpx) -> *mut libc::utmpx;
        fn setutxent();
        fn endutxent();
    }

    fn copy_to_cstring_field(field: &mut [c_char], value: &str) {
        let cstr = CString::new(value).expect("CString::new failed");
        let buffer_len = field.len();
        let copy_len = buffer_len.min(cstr.to_bytes().len());
        unsafe {
            ptr::copy_nonoverlapping(cstr.as_ptr(), field.as_mut_ptr(), copy_len);
        }
        if copy_len < buffer_len {
            field[copy_len] = 0;
        }
    }

    pub(crate) fn record_login() {
        let args: Vec<String> = env::args().collect();
        if args.len() != 6 {
            print!("invalid args count");
            unsafe { exit(-1) };
        }

        let ttyname = args[1].strip_prefix("/dev/").unwrap_or(&args[1]);
        let username = &args[2];
        let pid: libc::pid_t = args[3].parse().expect("Invalid PID");
        let sid: libc::pid_t = args[4].parse().expect("Invalid SID");
        let ut_type: i16 = match args[5].as_str() {
            "LOGIN" => USER_PROCESS,
            "EXIT" => DEAD_PROCESS,
            _ => {
                print!("invalid login type");
                unsafe { exit(-1) };
            }
        };

        let mut new_entry: utmpx = unsafe { mem::zeroed() };

        copy_to_cstring_field(&mut new_entry.ut_user, username);
        copy_to_cstring_field(&mut new_entry.ut_line, ttyname);

        new_entry.ut_type = ut_type as _;
        new_entry.ut_pid = pid;
        new_entry.ut_session = sid.into();

        cfg_if::cfg_if! {
            if #[cfg(target_arch = "aarch64")] {
                let current_timestamp = unsafe { time(ptr::null_mut()) as i64 };
            } else {
                let current_timestamp = unsafe { time(ptr::null_mut()) as i32 };
            }
        }

        println!("Current timestamp: {}", current_timestamp);
        new_entry.ut_tv.tv_sec = current_timestamp.to_owned();
        copy_to_cstring_field(&mut new_entry.ut_host, "orcaterm");

        unsafe { setutxent() };
        if unsafe { pututxline(&new_entry as *const _) }.is_null() {
            unsafe { endutxent() };
            return;
        }
        unsafe { endutxent() };

        let wtmp_path = CString::new(_PATH_WTMP).expect("CString::new failed");
        unsafe { updwtmp(wtmp_path.as_ptr(), &new_entry as *const _) };

        return;
    }
}

#[cfg(unix)]
fn main() {
    use unix::record_login;
    record_login()
}

#[cfg(windows)]
fn main() {}
