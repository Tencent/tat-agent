use super::{PtySession, PtySystem};
use crate::common::consts::{
    self, BASH_PREEXC, BLOCK_INIT, COREOS_BASH_PREEXC, COREOS_BLOCK_INIT, PTY_FLAG_INIT_BLOCK,
};
use crate::executor::proc::BaseCommand;
use crate::executor::shell_command::{build_envs, cmd_path};
use libc::{self, waitpid, winsize};
use log::{error, info};
use std::fs::{create_dir_all, read_to_string, set_permissions, write, File, Permissions};
use std::io::Write;
use std::os::unix::prelude::{AsRawFd, CommandExt, FromRawFd, PermissionsExt, RawFd};
use std::path::Path;
use std::process::{Child, Command};
use std::ptr::null_mut;
use std::sync::{Arc, Mutex};
use std::{io, ptr};
use users::get_user_by_name;
use users::os::unix::UserExt;
use users::User;

struct Inner {
    master: File,
    child: Child,
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
            return Err(format!("openpty fail {}", io::Error::last_os_error()));
        };

        libc::fchown(slave, user.uid(), user.primary_group_id());
    }

    let master = unsafe { File::from_raw_fd(master) };
    let slave = unsafe { File::from_raw_fd(slave) };
    Ok((master, slave))
}

#[derive(Default)]
pub struct ConPtySystem {}

impl PtySystem for ConPtySystem {
    fn openpty(
        &self,
        user_name: &str,
        cols: u16,
        rows: u16,
        #[allow(dead_code)] flag: u32,
    ) -> Result<std::sync::Arc<dyn PtySession + Send + Sync>, String> {
        let user = get_user_by_name(user_name).ok_or(format!("user {} not exist", user_name))?;
        let shell_path = cmd_path("bash").ok_or("bash not exist".to_string())?;
        let home_path = user.home_dir().to_str().unwrap_or_else(|| "/tmp");

        let envs = build_envs(user_name, home_path, &shell_path);
        let (mut master, slave) = openpty(user.clone(), cols, rows)?;

        let mut cmd = Command::new("bash");
        unsafe {
            cmd.pre_exec(move || {
                for signo in &[
                    libc::SIGCHLD,
                    libc::SIGINT,
                    libc::SIGQUIT,
                    libc::SIGTERM,
                    libc::SIGALRM,
                ] {
                    libc::signal(*signo, libc::SIG_DFL);
                }

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
            .map_err(|e| format!("spwan err {}", e))?;

        if (flag & PTY_FLAG_INIT_BLOCK) != 0 {
            let init_block = format!("source {};clear\n", BLOCK_INIT);
            let _ = master.write(init_block.as_bytes());
        }

        return Ok(Arc::new(UnixPtySession {
            inner: Arc::new(Mutex::new(Inner { master, child })),
        }));
    }
}

pub struct UnixPtySession {
    inner: Arc<Mutex<Inner>>,
}

impl PtySession for UnixPtySession {
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
        inner.master.try_clone().map_err(|e| format!("err {}", e))
    }
}

impl Drop for UnixPtySession {
    fn drop(&mut self) {
        let pid = self.inner.lock().unwrap().child.id() as i32;
        BaseCommand::kill_process_group(pid as u32);
        unsafe {
            waitpid(pid, null_mut(), 0);
        }
    }
}

fn install_script(mem_data: String, path: &str) -> io::Result<()> {
    let file_data = read_to_string(path).unwrap_or_else(|_| "".to_string());
    if mem_data != file_data {
        //write
        let parent = Path::new(path).parent().unwrap();
        create_dir_all(parent)?;
        set_permissions(
            parent,
            Permissions::from_mode(consts::FILE_EXECUTE_PERMISSION_MODE),
        )?;
        write(path, mem_data)?;
        set_permissions(
            path,
            Permissions::from_mode(consts::FILE_EXECUTE_PERMISSION_MODE),
        )?;
    }
    Ok(())
}

pub(crate) fn install_scripts() {
    let is_coreos = match read_to_string("/etc/os-release") {
        Ok(data) => data.contains("CoreOS"),
        Err(_) => false,
    };
    info!("install_scripts is_coreos {}", is_coreos);
    let (pexec_path, init_path) = if is_coreos {
        (COREOS_BASH_PREEXC, COREOS_BLOCK_INIT)
    } else {
        (BASH_PREEXC, BLOCK_INIT)
    };

    let mem_data = String::from_utf8_lossy(include_bytes!("../../misc/bash-preexec.sh"));
    let _ = install_script(mem_data.to_string(), pexec_path).map_err(|e| {
        error!("install_scripts {} fail {}", pexec_path, e);
    });
    let mem_data = String::from_utf8_lossy(include_bytes!("../../misc/bash-init.sh"));
    let _ = install_script(mem_data.to_string(), init_path).map_err(|e| {
        error!("install_scripts {} fail {}", init_path, e);
    });
}
