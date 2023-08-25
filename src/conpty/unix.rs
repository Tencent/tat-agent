use super::{PtyAdapter, PtyBase, PTY_INSPECT_READ};
use crate::executor::unix::{build_envs, cmd_path};
use std::fs::{metadata, File};
use std::io::{Read, Write};
use std::os::linux::fs::MetadataExt;
use std::os::unix::prelude::{AsRawFd, CommandExt, FromRawFd, RawFd};
use std::process::{Child, Command};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::{env, io, ptr};

use libc::{self, waitpid, winsize, SIGHUP};
use log::error;
use unix_mode::{is_allowed, Access, Accessor};
use users::os::unix::UserExt;
use users::{get_user_by_name, User};

struct Inner {
    master: File,
    child: Child,
    user: User,
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
        let shell_path = cmd_path("bash").ok_or("bash not exist".to_string())?;
        let home_path = user.home_dir().to_str().unwrap_or_else(|| "/tmp");

        let envs = build_envs(user_name, home_path, &shell_path);
        let (master, slave) = openpty(user.clone(), cols, rows)?;

        let mut cmd = Command::new("bash");
        unsafe {
            cmd.pre_exec(move || {
                libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGHUP);
                if libc::setsid() == -1 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = cmd
            .args(["--login"])
            .uid(user.uid())
            .gid(user.primary_group_id())
            .stdin(slave.try_clone().unwrap())
            .stdout(slave.try_clone().unwrap())
            .stderr(slave.try_clone().unwrap())
            .envs(envs)
            .current_dir(home_path)
            .spawn()
            .map_err(|e| format!("spawn error: {}", e))?;

        return Ok(Arc::new(UnixPtySession {
            inner: Arc::new(Mutex::new(Inner {
                master,
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
        let pid = self.inner.lock().unwrap().child.id() as i32;
        unsafe {
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
