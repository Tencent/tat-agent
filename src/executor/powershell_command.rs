use crate::daemonizer::wow64_disable_exc;
use crate::executor::proc::{BaseCommand, MyCommand};
use crate::start_failed_err_info;
use async_trait::async_trait;
use core::mem;
use libc::{c_void, free, malloc, memcpy};
use log::{debug, error, info, warn};
use ntapi::ntpsapi::{
    NtResumeProcess, NtSetInformationProcess, ProcessAccessToken, PROCESS_ACCESS_TOKEN,
};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::fs::{remove_file, File, OpenOptions};
use std::io::Write;
use std::os::windows::prelude::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::process::Stdio;
use std::ptr::null_mut;
use std::sync::Arc;
use std::{fmt, slice};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use winapi::shared::minwindef::{DWORD, FALSE, LPDWORD, LPVOID, ULONG, USHORT};
use winapi::shared::ntdef::{LPWSTR, LUID, NTSTATUS, NULL, PCHAR, PVOID};

use winapi::shared::winerror::ERROR_ACCESS_DENIED;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};

use winapi::um::lsalookup::{LSA_STRING, PLSA_STRING};
use winapi::um::minwinbase::LPSECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::CreateNamedPipeW;
use winapi::um::ntlsa::{
    LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaLogonUser, LsaLookupAuthenticationPackage,
    LsaRegisterLogonProcess, LSA_OPERATIONAL_MODE,
};
use winapi::um::ntsecapi::{MsV1_0S4ULogon, MSV1_0_S4U_LOGON};
use winapi::um::processthreadsapi::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken, TerminateProcess,
};
use winapi::um::securitybaseapi::{AllocateLocallyUniqueId, DuplicateTokenEx};
use winapi::um::subauth::UNICODE_STRING;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, LPPROCESSENTRY32, PROCESSENTRY32,
    TH32CS_SNAPPROCESS,
};
use winapi::um::userenv::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use winapi::um::winbase::{
    GetUserNameW, CREATE_SUSPENDED, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use crate::common::strwsz::{str2wsz, wsz2string};
use winapi::um::winnt::{
    RtlZeroMemory, SecurityImpersonation, TokenPrimary, HANDLE, PROCESS_ALL_ACCESS,
    PROCESS_TERMINATE, PTOKEN_GROUPS, QUOTA_LIMITS, TOKEN_ALL_ACCESS, TOKEN_SOURCE,
};

pub struct PowerShellCommand {
    base: Arc<BaseCommand>,
    token: File,
}

impl PowerShellCommand {
    pub fn new(
        cmd_path: &str,
        username: &str,
        work_dir: &str,
        timeout: u64,
        bytes_max_report: u64,
        log_file_path: &str,
        cos_bucket: &str,
        cos_prefix: &str,
        task_id: &str,
    ) -> PowerShellCommand {
        let cmd_path = String::from(cmd_path).replace(" ", "` ");
        PowerShellCommand {
            base: Arc::new(BaseCommand::new(
                cmd_path.as_str(),
                username,
                work_dir,
                timeout,
                bytes_max_report,
                log_file_path,
                cos_bucket,
                cos_prefix,
                task_id,
            )),
            token: unsafe { File::from_raw_handle(0 as HANDLE) },
        }
    }

    fn work_dir_check(&self) -> Result<(), String> {
        if !wow64_disable_exc(|| Path::new(self.base.work_dir.as_str()).exists()) {
            let ret = format!(
                "PowerShellCommand {} start fail, working_directory:{}, username: {}: working directory not exists",
                self.base.cmd_path, self.base.work_dir, self.base.username
            );
            *self.base.err_info.lock().unwrap() =
                start_failed_err_info!(ERR_WORKING_DIRECTORY_NOT_EXISTS, self.base.work_dir);
            return Err(ret);
        };
        Ok(())
    }

    fn prepare_cmd(&mut self, theirs: File) -> Result<Command, String> {
        let std_out = theirs.try_clone().map_err(|e| {
            *self.base.err_info.lock().unwrap() = e.to_string();
            error!("prepare_cmd,clone pipe  std_out fail {}", e);
            e.to_string()
        })?;

        let std_err = theirs.try_clone().map_err(|e| {
            *self.base.err_info.lock().unwrap() = e.to_string();
            error!("prepare_cmd,clone pipe  std_err fail {}", e);
            e.to_string()
        })?;

        let mut command = Command::new("cmd.exe");
        command
            .args(&[
                "/C",
                "powershell",
                "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8",
                "&",
                "powershell",
                "-ExecutionPolicy",
                "Bypass",
                self.base.cmd_path.as_str(),
            ])
            .stdin(Stdio::null())
            .stdout(std_out)
            .stderr(std_err)
            .current_dir(self.base.work_dir.as_str())
            .creation_flags(CREATE_SUSPENDED); //create as suspend

        self.token = get_user_token(&self.base.username).map_err(|err| {
            *self.base.err_info.lock().unwrap() = err.clone();
            err
        })?;

        let mut envs = HashMap::<String, String>::new();
        if !get_current_user().eq_ignore_ascii_case(&self.base.username) {
            load_environment(self.token.as_raw_handle(), &mut envs);
            if envs.len() != 0 {
                command.env_clear().envs(envs);
            }
        }
        Ok(command)
    }

    fn resume_as_user(&self) {
        let pid = self.pid();
        unsafe {
            let process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            let current_user = get_current_user();
            if !current_user.eq_ignore_ascii_case(&self.base.username) {
                let mut access_token = PROCESS_ACCESS_TOKEN {
                    Token: self.token.as_raw_handle(),
                    Thread: 0 as HANDLE,
                };
                let status = NtSetInformationProcess(
                    process,
                    ProcessAccessToken,
                    &mut access_token as *mut PROCESS_ACCESS_TOKEN as PVOID,
                    mem::size_of::<PROCESS_ACCESS_TOKEN>() as u32,
                );
                info!("NtSetInformationProcess result is {}", status);
            }
            NtResumeProcess(process);
            CloseHandle(process);
        }
    }

    fn spawn_cmd(&mut self, pipe: File) -> Result<Child, String> {
        //spawn suspended process
        let child = self.prepare_cmd(pipe)?.spawn().map_err(|e| {
            *self.base.err_info.lock().unwrap() = e.to_string();
            // remove log_file when process run failed.
            if let Err(e) = remove_file(self.base.log_file_path.as_str()) {
                warn!("remove log file failed: {:?}", e)
            }
            format!(
                "PowerShellCommand {}, working_directory:{}, start fail: {}",
                self.base.cmd_path, self.base.work_dir, e
            )
        })?;
        *self.base.pid.lock().unwrap() = Some(child.id());
        self.resume_as_user();
        Ok(child)
    }
}

#[async_trait]
impl MyCommand for PowerShellCommand {
    async fn run(&mut self) -> Result<(), String> {
        info!("=>PowerShellCommand::run()");
        // store path check
        self.store_path_check()?;

        // work dir check
        self.work_dir_check()?;

        // create pipe
        let (our_pipe, their_pipe) = anon_pipe(true)?;

        let log_file = self.open_log_file()?;

        let mut child = self.spawn_cmd(their_pipe)?;

        let base = self.base.clone();
        info!("=>PowerShellCommand::tokio::spawn");
        // async read output.
        tokio::spawn(async move {
            base.add_timeout_timer();
            base.read_ps1_output(our_pipe, log_file).await;
            base.del_timeout_timer();
            base.process_finish(&mut child).await;
        });
        Ok(())
    }

    fn debug(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt(f)
    }
    fn get_base(&self) -> Arc<BaseCommand> {
        self.base.clone()
    }
}

impl BaseCommand {
    async fn read_ps1_output(&self, file: File, mut log_file: File) {
        let mut utf8_bom_checked = false;
        let pid = self.pid.lock().unwrap().unwrap();
        const BUF_SIZE: usize = 1024;
        let mut buffer: [u8; BUF_SIZE] = [0; BUF_SIZE];
        let mut file = tokio::fs::File::from_std(file);
        loop {
            let size = file.read(&mut buffer[..]).await;
            if size.is_err() {
                error!("read output err:{}, pid:{}", size.unwrap_err(), pid);
                break;
            }
            let mut len = size.unwrap();
            if len > 0 {
                //win2008 check utf8 bom header, start with 0xEE,0xBB,0xBF,
                if utf8_bom_checked == false {
                    utf8_bom_checked = true;
                    let utf8_bom_header: [u8; 3] = [0xEF, 0xBB, 0xBF];
                    if buffer.starts_with(&utf8_bom_header[..]) {
                        buffer.rotate_left(3);
                        len = len - 3;
                    }
                }
                let output_string = String::from_utf8_lossy(&buffer[..len]);
                debug!("output:[{}], pid:{}, len:{}", output_string, pid, len);

                if let Err(e) = log_file.write(&buffer[..len]) {
                    error!("write output file fail: {:?}", e)
                }
                self.append_output(&buffer[..len]);
            } else {
                info!("read output finished normally, pid:{}", pid);
                break;
            }
        }

        if let Err(e) = log_file.sync_all() {
            error!("sync in-memory data to file fail: {:?}", e)
        }

        self.finish_logging().await;
    }

    pub fn kill_process_group(pid: u32) {
        info!("=>kill_process_group, pid{}", pid);
        unsafe {
            let mut proc_list: Vec<(u32, u32)> = Vec::new();
            let mut child_pids: Vec<u32> = Vec::new();

            //get process snapshot
            let hp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
            let mut pe: PROCESSENTRY32 = mem::zeroed();
            pe.dwSize = mem::size_of::<PROCESSENTRY32>() as DWORD;
            if 0 != Process32First(hp, &mut pe as LPPROCESSENTRY32) {
                loop {
                    proc_list.push((pe.th32ParentProcessID, pe.th32ProcessID));
                    if 0 == Process32Next(hp, &mut pe as LPPROCESSENTRY32) {
                        break;
                    }
                }
            }
            CloseHandle(hp);

            //find all child process
            child_pids.push(pid);
            let mut index = 0;
            loop {
                if index != child_pids.len() {
                    for (_, (ppid, pid)) in proc_list.iter().enumerate() {
                        if *ppid == *child_pids.get(index).unwrap() {
                            child_pids.push(*pid);
                        }
                    }
                    index = index + 1;
                } else {
                    break;
                }
            }

            //kill process
            for (_, pid) in child_pids.iter().enumerate() {
                info!("pid need to kill is {}", pid);
                let handle = OpenProcess(PROCESS_TERMINATE, FALSE, *pid);
                if handle != NULL {
                    TerminateProcess(handle, 0xffffffff as u32);
                    CloseHandle(handle);
                } else {
                    error!("open pid err, {}", GetLastError());
                }
            }
        }
    }
}

impl Debug for PowerShellCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.base.fmt(f)
    }
}

pub fn anon_pipe(ours_readable: bool) -> Result<(File, File), String> {
    unsafe {
        let mut tries = 0;
        let mut name;
        let ours: File;
        loop {
            tries += 1;
            name = format!(
                r"\\.\pipe\__tat_anon_pipe__.{}.{}",
                GetCurrentProcessId(),
                thread_rng()
                    .sample_iter(&Alphanumeric)
                    .take(10)
                    .collect::<String>(),
            );

            let wide_name = str2wsz(&name);
            let mut flags = FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
            if ours_readable {
                flags |= PIPE_ACCESS_INBOUND;
            } else {
                flags |= PIPE_ACCESS_OUTBOUND;
            }

            let handle = CreateNamedPipeW(
                wide_name.as_ptr(),
                flags,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                4096,
                4096,
                0,
                null_mut(),
            );

            if handle == INVALID_HANDLE_VALUE {
                let err = GetLastError();
                if tries < 10 {
                    if err == ERROR_ACCESS_DENIED {
                        continue;
                    }
                }
                error!("creat namepipe fail,{}", err);
                return Err(format!("creat namepipe fail,{}", err));
            }
            ours = File::from_raw_handle(handle);
            break;
        }

        let mut opts = OpenOptions::new();
        opts.write(ours_readable);
        opts.read(!ours_readable);

        let theirs = opts.open(Path::new(&name)).map_err(|e| e.to_string())?;
        Ok((ours, theirs))
    }
}

pub fn get_current_user() -> String {
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

pub fn load_environment(token: HANDLE, envs: &mut HashMap<String, String>) {
    unsafe {
        let mut environment: PVOID = null_mut();
        if 0 != CreateEnvironmentBlock(&mut environment as *mut LPVOID, token, FALSE) {
            let data = slice::from_raw_parts(environment as *const u16, usize::MAX);
            let mut start = 0;
            loop {
                let item = wsz2string(data[start..].as_ptr());
                if item.len() == 0 {
                    break;
                }
                let env_part: Vec<&str> = item.splitn(2, '=').collect();
                if env_part.len() == 2 {
                    envs.insert(env_part[0].to_string(), env_part[1].to_string());
                }
                start = start + item.chars().count() + 1;
            }
            DestroyEnvironmentBlock(environment as LPVOID);
        }
    }
}

fn create_user_token(user_name: &str) -> Result<File, String> {
    info!("=>enter create_user_token");
    unsafe {
        let mut mode: LSA_OPERATIONAL_MODE = mem::zeroed();

        let mut tat_name = "tat".to_string();
        let mut tat_lsa = LSA_STRING {
            Length: tat_name.len() as USHORT,
            MaximumLength: tat_name.len() as USHORT,
            Buffer: tat_name.as_mut_ptr() as PCHAR,
        };

        let mut lsa_handle = 0 as HANDLE;
        let mut status =
            LsaRegisterLogonProcess(&mut tat_lsa as PLSA_STRING, &mut lsa_handle, &mut mode);
        if status != 0 {
            return Err(format!("RegisterLogonProcess Fail {}", status));
        }

        let mut pkg_name = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0".to_string();
        let mut auth_package_name = LSA_STRING {
            Length: pkg_name.len() as USHORT,
            MaximumLength: pkg_name.len() as USHORT,
            Buffer: pkg_name.as_mut_ptr() as PCHAR,
        };
        let mut auth_package_id: ULONG = 0;
        LsaLookupAuthenticationPackage(lsa_handle, &mut auth_package_name, &mut auth_package_id);

        let logon_info_size =
            mem::size_of::<MSV1_0_S4U_LOGON>() + (user_name.len() + ".".len()) * 2;
        let buffer = malloc(logon_info_size) as *mut u8;
        RtlZeroMemory(buffer as *mut c_void, logon_info_size);

        let s4u_logon = buffer as *mut MSV1_0_S4U_LOGON;
        (*s4u_logon).MessageType = MsV1_0S4ULogon;
        (*s4u_logon).MSV1_0_LOGON_SUBMIT_TYPE = 0;
        let name_buffer = buffer.add(mem::size_of::<MSV1_0_S4U_LOGON>());

        let wname = str2wsz(user_name);
        let wname_size = (wname.len() - 1) * 2;
        memcpy(
            name_buffer as *mut c_void,
            wname.as_ptr() as *const c_void,
            wname_size,
        );
        (*s4u_logon).UserPrincipalName = UNICODE_STRING {
            Length: wname_size as USHORT,
            MaximumLength: wname_size as USHORT,
            Buffer: name_buffer as *mut u16,
        };

        let wdomain = str2wsz(".");
        let wdomain_size = (wdomain.len() - 1) * 2;

        let domain_buffer = name_buffer.add((wname.len() - 1) * 2);
        memcpy(
            domain_buffer as *mut c_void,
            wdomain.as_ptr() as *const c_void,
            wdomain_size,
        );
        (*s4u_logon).DomainName = UNICODE_STRING {
            Length: wdomain_size as USHORT,
            MaximumLength: wdomain_size as USHORT,
            Buffer: domain_buffer as *mut u16,
        };

        let mut source_context: TOKEN_SOURCE = mem::zeroed();
        memcpy(
            source_context.SourceName.as_mut_ptr() as *mut c_void,
            tat_name.as_ptr() as *const c_void,
            (wdomain.len() - 1) * 2,
        );
        AllocateLocallyUniqueId(&mut source_context.SourceIdentifier);

        let mut profile: PVOID = NULL;
        let mut profile_size: DWORD = 0;

        let mut logon_id = LUID {
            LowPart: 0,
            HighPart: 0,
        };

        let mut token = 0 as HANDLE;
        let mut quotas: QUOTA_LIMITS = mem::zeroed();
        let mut sub_status: NTSTATUS = 0;

        status = LsaLogonUser(
            lsa_handle,
            &mut tat_lsa,
            3, //SECURITY_LOGON_TYPE::Network
            auth_package_id,
            s4u_logon as PVOID,
            logon_info_size as ULONG,
            NULL as PTOKEN_GROUPS,
            &mut source_context,
            &mut profile,
            &mut profile_size,
            &mut logon_id,
            &mut token,
            &mut quotas,
            &mut sub_status,
        );

        free(buffer as *mut c_void);
        LsaDeregisterLogonProcess(lsa_handle);
        if profile != null_mut() {
            LsaFreeReturnBuffer(profile);
        }
        if status != 0 {
            return Err(format!("LsaLogonUser Fail,{}", status));
        }

        let _token = File::from_raw_handle(token); // for auto close
        let mut primary_token = 0 as HANDLE;
        DuplicateTokenEx(
            _token.as_raw_handle(),
            TOKEN_ALL_ACCESS,
            null_mut() as LPSECURITY_ATTRIBUTES,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token,
        );
        return if primary_token != null_mut() {
            Ok(File::from_raw_handle(primary_token))
        } else {
            Err(format!("DuplicateTokenEx Fail,{}", GetLastError()))
        };
    }
}

pub fn get_user_token(user_name: &str) -> Result<File, String> {
    static mut IS_2008: Option<bool> = None;
    let is_2008 = unsafe {
        IS_2008.get_or_insert_with(|| {
            let output = std::process::Command::new("wmic")
                .args(&["os", "get", "Caption"])
                .stdout(Stdio::piped())
                .output()
                .unwrap();
            let version = String::from_utf8_lossy(&output.stdout);
            info!("version is {}", version);
            let result = version.contains("2008");
            result
        })
    };

    if get_current_user().eq_ignore_ascii_case(user_name) || *is_2008 {
        let mut token: HANDLE = 0 as HANDLE;
        unsafe {
            if 0 == OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token) {
                return Err(format!("OpenProcessToken Fail {}", GetLastError()));
            }
            return Ok(File::from_raw_handle(token));
        }
    }
    return create_user_token(user_name);
}

#[cfg(test)]
mod test {
    use crate::executor::powershell_command::anon_pipe;
    use std::io::{Read, Write};
    #[test]
    fn test() {
        let (mut ours, mut theirs) = anon_pipe(true).unwrap();
        theirs.write("test".as_bytes()).unwrap();
        let mut buffer = [0; 1024];
        let size = ours.read(&mut buffer).unwrap();
        let result = String::from_utf8_lossy(&buffer[0..size]);
        assert_eq!(result, "test".to_string());
        return;
    }
}
