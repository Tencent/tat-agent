use super::{PtyAdapter, PtyBase, PTY_INSPECT_READ};
use crate::executor::unix::build_envs;
use libc::{
    self, getsid, pid_t, ttyname, uid_t, waitpid, winsize, SIGHUP, STDIN_FILENO, TIOCSCTTY,
};
use log::{error, info};
use std::ffi::CStr;
use std::fs::{metadata, File};
use std::io::{Read, Write};
use std::os::linux::fs::MetadataExt;
use std::os::unix::prelude::{AsRawFd, CommandExt, FromRawFd, RawFd};
use std::path::Path;
use std::process::{Child, Command};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::{env, io, ptr};
use unix_mode::{is_allowed, Access, Accessor};
use users::os::unix::UserExt;
use users::{get_user_by_name, User};

fn call_utmpx(ttyname: &str, username: &str, pid: libc::pid_t, sid: libc::pid_t, ut_type: &str) {
    info!(
        "=>call_utmpx tty:{} user:{} pid:{} sid:{} type:{}",
        ttyname, username, pid, sid, ut_type
    );
    let current_bin = env::current_exe().expect("current path failed");
    let current_path = current_bin.parent().expect("parent path failed");
    let utmpx_path = format!("{}/utmpx", current_path.to_string_lossy());
    match Command::new(utmpx_path)
        .arg(ttyname)
        .arg(username)
        .arg(pid.to_string())
        .arg(sid.to_string())
        .arg(ut_type)
        .output()
    {
        Ok(output) => {
            info!(
                "stdout:{}  stderr:{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        Err(err) => {
            info!("call_utmpx  err:{}", err);
        }
    }
}

fn audit_setloginuid(uid: uid_t) -> Result<(), std::io::Error> {
    info!("=>audit_setloginuid {}", uid);
    let loginuid = format!("{}", uid);
    let loginuid_path = format!("/proc/self/loginuid");

    let mut file = File::create(loginuid_path)?;
    file.write_all(loginuid.as_bytes())?;
    Ok(())
}

struct Inner {
    master: File,
    child: Child,
    user: User,
    tty_name: String,
}

fn openpty(user: User, cols: u16, rows: u16) -> Result<(File, File), String> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;

    let mut size = winsize {
        ws_col: cols,
        ws_row: rows,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    unsafe {
        if 0 != libc::openpty(
            &mut master,
            &mut slave,
            ptr::null_mut(),
            ptr::null_mut(),
            &mut size,
        ) {
            return Err(format!("openpty failed: {}", io::Error::last_os_error()));
        };

        libc::fchown(slave, user.uid(), user.primary_group_id());
    }

    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    Ok((master, slave))
}

#[derive(Default)]
pub struct ConPtyAdapter {}

impl PtyAdapter for ConPtyAdapter {
    fn openpty(
        &self,
        user_name: &str,
        cols: u16,
        rows: u16,
        #[allow(dead_code)] _flag: u32,
    ) -> Result<std::sync::Arc<dyn PtyBase + Send + Sync>, String> {
        let user = get_user_by_name(user_name).ok_or(format!("user {} not exist", user_name))?;
        let shell_path = user.shell();
        let shell_name = Path::new(shell_path)
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("bash"))
            .to_string_lossy()
            .to_string();

        let home_path = user.home_dir().to_str().unwrap_or_else(|| "/tmp");
        let envs = build_envs(user_name, home_path, &shell_path.to_string_lossy());
        let (master, slave) = openpty(user.clone(), cols, rows)?;
        let mut cmd = Command::new(shell_name);
        unsafe {
            let uid = user.uid();
            let gid = user.primary_group_id();
            cmd.pre_exec(move || {
                audit_setloginuid(uid)?;
                libc::setgid(gid);
                libc::setuid(uid);
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP);
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                libc::ioctl(STDIN_FILENO, TIOCSCTTY, 0);
                libc::tcsetpgrp(STDIN_FILENO, libc::getpid());
                Ok(())
            });
        }
        let child = cmd
            .stdin(slave.try_clone().expect(""))
            .stdout(slave.try_clone().expect(""))
            .stderr(slave.try_clone().expect(""))
            .envs(envs)
            .current_dir(home_path)
            .spawn()
            .map_err(|e| format!("spawn error: {}", e))?;

        let pid = child.id() as pid_t;
        let sid = unsafe { getsid(pid) };
        let utmx_type = "LOGIN";
        let tty_name = unsafe {
            let tty_name_c = ttyname(slave.as_raw_fd());
            CStr::from_ptr(tty_name_c).to_string_lossy().to_string()
        };
        call_utmpx(&tty_name.clone(), user_name, pid, sid, &utmx_type);

        return Ok(Arc::new(UnixPtySession {
            inner: Arc::new(Mutex::new(Inner {
                master,
                tty_name,
                child,
                user,
            })),
        }));
    }
}

pub struct UnixPtySession {
    inner: Arc<Mutex<Inner>>,
}

impl UnixPtySession {
    fn get_cwd(&self) -> String {
        if let Ok(pid) = self.get_pid() {
            let cwd_path = format!("/proc/{}/cwd", pid);
            if let Ok(path) = std::fs::read_link(&cwd_path) {
                return path.to_string_lossy().to_string();
            };
        }
        return "/tmp".to_owned();
    }
}

impl PtyBase for UnixPtySession {
    fn resize(&self, cols: u16, rows: u16) -> Result<(), String> {
        let size = winsize {
            ws_row: rows,
            ws_col: cols,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };

        let result = unsafe {
            let inner = self.inner.lock().unwrap();
            libc::ioctl(
                inner.master.as_raw_fd(),
                libc::TIOCSWINSZ,
                &size as *const _,
            )
        };
        if result != 0 {
            Err(format!("{}", io::Error::last_os_error()))
        } else {
            Ok(())
        }
    }

    fn get_reader(&self) -> Result<std::fs::File, std::string::String> {
        self.get_writer()
    }

    fn get_writer(&self) -> Result<std::fs::File, std::string::String> {
        let inner = self.inner.lock().unwrap();
        inner.master.try_clone().map_err(|e| format!("error: {e}"))
    }

    fn get_pid(&self) -> Result<u32, String> {
        let pid = self.inner.lock().unwrap().child.id();
        Ok(pid)
    }

    fn execute(&self, f: &dyn Fn() -> Result<Vec<u8>, String>) -> Result<Vec<u8>, String> {
        let user = self.inner.lock().expect("inner lock failed").user.clone();
        let cwd_path = self.get_cwd();
        unsafe {
            let mut pipefd: [i32; 2] = [0, 0];
            libc::pipe(pipefd.as_mut_ptr());
            let pid = libc::fork();
            if pid == 0 {
                let _ = env::set_current_dir(cwd_path);
                libc::setgid(user.primary_group_id());
                libc::setuid(user.uid());
                let mut stdin = File::from_raw_fd(pipefd[1]);
                match f() {
                    Ok(output) => {
                        let _ = stdin.write_all(&output);
                        libc::exit(0);
                    }
                    Err(err_msg) => {
                        //error!("[child] work_as_user func exit failed: {}", err_msg);
                        let _ = stdin.write_all(err_msg.as_bytes());
                        libc::exit(1);
                    }
                }
            } else {
                libc::close(pipefd[1]);
                let mut output: Vec<u8> = Vec::new();
                let mut stdout = File::from_raw_fd(pipefd[0]);
                let _ = stdout.read_to_end(&mut output);
                let mut exit_code = 0 as i32;
                libc::waitpid(pid, &mut exit_code, 0);
                if exit_code == 0 {
                    return Ok(output);
                } else {
                    let err_msg = String::from_utf8_lossy(&output).to_string();
                    error!("[parent] work_as_user func exit failed: {}", err_msg);
                    return Err(err_msg);
                }
            }
        }
    }

    fn inspect_access(&self, path: &str, access: u8) -> Result<(), String> {
        let meta_data = metadata(path).map_err(|e| e.to_string())?;

        let user = self.inner.lock().unwrap().user.clone();
        let access = if access == PTY_INSPECT_READ {
            Access::Read
        } else {
            Access::Write
        };
        //check owner
        if meta_data.st_uid() == user.uid()
            && is_allowed(Accessor::User, access, meta_data.st_mode())
        {
            return Ok(());
        }
        //check group
        if user.primary_group_id() == meta_data.st_gid()
            && is_allowed(Accessor::Group, access, meta_data.st_mode())
        {
            return Ok(());
        }
        if let Some(groups) = user.groups() {
            for group in groups {
                if group.gid() == meta_data.st_gid()
                    && is_allowed(Accessor::Group, access, meta_data.st_mode())
                {
                    return Ok(());
                }
            }
        }
        //check others
        if is_allowed(Accessor::Other, access, meta_data.st_mode()) {
            return Ok(());
        }
        Err("access denied".to_string())
    }
}

impl Drop for UnixPtySession {
    fn drop(&mut self) {
        let pid = self.inner.lock().expect("").child.id() as i32;
        let user = self.inner.lock().expect("").user.clone();
        let tty_name = self.inner.lock().expect("").tty_name.clone();

        unsafe {
            let user_name = user.name().to_string_lossy().to_string();
            let sid = getsid(pid);
            let utmx_type = "EXIT";
            call_utmpx(&tty_name, &user_name, pid, sid, &utmx_type);
            libc::kill(pid * -1, SIGHUP);
            waitpid(pid, null_mut(), 0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use users::get_current_username;
    #[test]
    fn test_work_as_user() {
        let name = get_current_username().unwrap();
        let user_name = String::from(name.to_str().unwrap());
        let pty_session = ConPtyAdapter::default()
            .openpty(&user_name, 100, 100, 0)
            .unwrap();
        let result = pty_session
            .execute(&|| Ok("foo".to_string().into_bytes()))
            .unwrap();

        let foo = String::from_utf8_lossy(&result).to_string();
        assert_eq!(foo, "foo");
    }
}
