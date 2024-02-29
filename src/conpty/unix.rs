use super::{
    PtyAdapter, PtyBase, PtyExecCallback, PtyResult, PTY_EXEC_DATA_SIZE, PTY_INSPECT_READ,
};
use crate::executor::unix::build_envs;

use std::ffi::CStr;
use std::fs::{metadata, File};
use std::io::{Read as _, Write as _};
use std::os::linux::fs::MetadataExt;
use std::os::unix::prelude::{AsRawFd, CommandExt, FromRawFd, RawFd};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{env, io, ptr};

use libc::{
    self, getsid, pid_t, ttyname, uid_t, waitpid, winsize, SIGHUP, STDIN_FILENO, TIOCSCTTY,
};
use log::{error, info};
use tokio::io::{AsyncReadExt as _, BufReader};
use tokio::time::Instant;
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

fn openpty(user: User, cols: u16, rows: u16) -> PtyResult<(File, File)> {
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
    ) -> PtyResult<Arc<dyn PtyBase + Send + Sync>> {
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
    fn resize(&self, cols: u16, rows: u16) -> PtyResult<()> {
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

    fn get_reader(&self) -> PtyResult<File> {
        self.get_writer()
    }

    fn get_writer(&self) -> PtyResult<File> {
        let inner = self.inner.lock().unwrap();
        inner.master.try_clone().map_err(|e| format!("error: {e}"))
    }

    fn get_pid(&self) -> PtyResult<u32> {
        let pid = self.inner.lock().unwrap().child.id();
        Ok(pid)
    }

    fn inspect_access(&self, path: &str, access: u8) -> PtyResult<()> {
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

    fn execute(&self, f: &dyn Fn() -> PtyResult<Vec<u8>>) -> PtyResult<Vec<u8>> {
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
                }
                let err_msg = String::from_utf8_lossy(&output).to_string();
                error!("[parent] work_as_user func exit failed: {}", err_msg);
                return Err(err_msg);
            }
        }
    }

    fn execute_stream(
        &self,
        cmd: Command,
        callback: Option<PtyExecCallback>,
        timeout: Option<u64>,
    ) -> PtyResult<()> {
        let user = self.inner.lock().expect("inner lock failed").user.clone();
        let cwd_path = self.get_cwd();
        tokio::runtime::Builder::new()
            .basic_scheduler()
            .enable_all()
            .build()
            .expect("runtime build failed")
            .block_on(async move {
                let mut idx = 0u32;
                let mut is_last;
                let callback = callback.unwrap_or(Box::new(|_, _, _, _| ()));
                let timeout_at = Instant::now() + Duration::from_secs(timeout.unwrap_or(60));
                let mut child = unsafe {
                    tokio::process::Command::from(cmd)
                        .stdout(Stdio::piped())
                        .current_dir(cwd_path)
                        .uid(user.uid())
                        .gid(user.primary_group_id())
                        .pre_exec(|| {
                            libc::dup2(1, 2);
                            Ok(())
                        })
                        .spawn()
                        .map_err(|_| "command start failed")
                }?;
                let mut reader = BufReader::new(child.stdout.take().unwrap());
                loop {
                    let mut buf = [0u8; PTY_EXEC_DATA_SIZE];
                    tokio::select! {
                        _ = tokio::time::delay_until(timeout_at) => {
                            error!("work_as_user func timeout");
                            child.kill().map_err(|_| "command timeout, kill failed")?;
                            Err(  "command timeout, process killed" )?;
                        }
                        len = reader.read(&mut buf) => {
                            let len = len.map_err(|_| "buffer read failed")?;
                            is_last = len == 0;
                            if is_last {
                                break;
                            }
                            callback(idx, is_last, None, Vec::from(&buf[..len]));
                            idx += 1;
                        }
                    };
                }

                let exit_status = child
                    .wait_with_output()
                    .await
                    .map_err(|_| "wait command failed")?
                    .status;
                if !exit_status.success() {
                    error!("work_as_user func exit failed: {}", exit_status);
                }
                let exit_code = exit_status.code().ok_or("command terminated abnormally")?;
                callback(idx, is_last, Some(exit_code), Vec::new());
                Ok(())
            })
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
    use std::collections::HashMap;
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

    #[test]
    fn test_work_as_user_stream() {
        let params = vec![
            (
                // Below data length with stderr
                "echo -n foo >&2 ",
                None,
                HashMap::from([
                    (0, (false, None, b"foo".to_vec())),
                    (1, (true, Some(0), vec![])),
                ]),
                Ok(()),
            ),
            (
                // Below data length multiple outputs
                "echo -n foo; sleep 0.5; echo -n foo;",
                None,
                HashMap::from([
                    (0, (false, None, b"foo".to_vec())),
                    (1, (false, None, b"foo".to_vec())),
                    (2, (true, Some(0), vec![])),
                ]),
                Ok(()),
            ),
            (
                // Exceeding data length
                "echo -n foo; echo -n foo;",
                None,
                HashMap::from([
                    (0, (false, None, b"foofo".to_vec())),
                    (1, (false, None, b"o".to_vec())),
                    (2, (true, Some(0), vec![])),
                ]),
                Ok(()),
            ),
            (
                // Timeout without output
                "while true; do sleep 100; done",
                Some(1),
                HashMap::new(),
                Err("command timeout, process killed".to_owned()),
            ),
            (
                // Timeout with exceeding data length multiple output
                "while true; do echo -n foofoo; sleep 0.5; done",
                Some(1),
                HashMap::from([
                    (0, (false, None, b"foofo".to_vec())),
                    (1, (false, None, b"o".to_vec())),
                    (2, (false, None, b"foofo".to_vec())),
                    (3, (false, None, b"o".to_vec())),
                ]),
                Err("command timeout, process killed".to_owned()),
            ),
            (
                // Failed without output
                "exit 1",
                None,
                HashMap::from([(0, (true, Some(1), vec![]))]),
                Ok(()),
            ),
            (
                // Failed with output
                "echo -n foo; exit 1",
                None,
                HashMap::from([
                    (0, (false, None, b"foo".to_vec())),
                    (1, (true, Some(1), vec![])),
                ]),
                Ok(()),
            ),
        ];

        for p in params {
            test_execute_stream_template(p.0, p.1, p.2, p.3);
        }
    }

    fn test_execute_stream_template(
        script: &str,
        timeout: Option<u64>,
        data_map: HashMap<u32, (bool, Option<i32>, Vec<u8>)>,
        expect_result: PtyResult<()>,
    ) {
        let name = get_current_username().unwrap();
        let user_name = String::from(name.to_str().unwrap());
        let pty_session = ConPtyAdapter::default()
            .openpty(&user_name, 100, 100, 0)
            .unwrap();
        let mut cmd = Command::new("sh");
        cmd.args(&["-c", script]);
        let cb = Box::new(
            move |idx: u32, is_last: bool, exit_code: Option<i32>, data: Vec<u8>| {
                let (expect_is_last, expect_exit_code, expect_data) = data_map
                    .get(&idx)
                    .expect(&format!("idx `{idx}` not expect"));
                assert_eq!(*expect_is_last, is_last);
                assert_eq!(*expect_exit_code, exit_code);
                assert_eq!(*expect_data, data);
            },
        );
        let res = pty_session.execute_stream(cmd, Some(cb), timeout);
        assert_eq!(expect_result, res);
    }
}
