use crate::common::utils::{gen_rand_str_with, get_current_username, str2wsz, wsz2string};
use crate::daemonizer::wow64_disable_exc;
use crate::executor::proc::Cmd;

use std::collections::HashMap;
use std::fs::{remove_file, File, OpenOptions};
use std::os::windows::prelude::{AsRawHandle, FromRawHandle};
use std::path::Path;
use std::process::Stdio;
use std::ptr::null_mut;
use std::sync::{Arc, LazyLock};
use std::{mem, slice};

use anyhow::{anyhow, Result};
use libc::{c_void, free, malloc, memcpy};
use log::{error, info, warn};
use ntapi::ntpsapi::{
    NtResumeProcess, NtSetInformationProcess, ProcessAccessToken, PROCESS_ACCESS_TOKEN,
};
use tokio::process::{Child, Command};

use winapi::shared::minwindef::{DWORD, FALSE, LPVOID, ULONG, USHORT};
use winapi::shared::ntdef::{LUID, NTSTATUS, NULL, PCHAR, PVOID};
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
    CREATE_SUSPENDED, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_INBOUND,
    PIPE_ACCESS_OUTBOUND, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use winapi::um::winnls::GetOEMCP;
use winapi::um::winnt::{
    RtlZeroMemory, SecurityImpersonation, TokenPrimary, HANDLE, PROCESS_ALL_ACCESS,
    PROCESS_TERMINATE, PTOKEN_GROUPS, QUOTA_LIMITS, TOKEN_ALL_ACCESS, TOKEN_SOURCE,
};

impl Cmd {
    fn work_dir_check(&self) -> Result<()> {
        if !wow64_disable_exc(|| Path::new(self.work_dir.as_str()).exists()) {
            *self.err_info.lock().unwrap() = format!(
                "DirectoryNotExists: working_directory `{}` not exists",
                self.work_dir
            );
            return Err(anyhow!("working directory not exists",));
        };
        Ok(())
    }

    fn prepare_cmd(&self, pipe: File) -> Result<Command> {
        info!("=>prepare_cmd");
        let command = if self.cmd_path.ends_with(".ps1") {
            info!("execute powershell command {}", self.cmd_path);
            init_powershell_cmd(&self.cmd_path)
        } else {
            info!("execute bat command {}", self.cmd_path);
            init_bat_cmd(&self.cmd_path)
        };

        prepare_cmd(command, &self.username, &self.work_dir, pipe)
            .inspect_err(|e| *self.err_info.lock().unwrap() = e.to_string().clone())
    }

    fn spawn_cmd(&self, pipe: File) -> Result<Child> {
        //spawn suspended process
        let child = self.prepare_cmd(pipe)?.spawn().inspect_err(|e| {
            *self.err_info.lock().unwrap() = e.to_string();
            // remove log_file when process run failed.
            let _ = remove_file(self.log_file_path.as_str())
                .inspect_err(|e| warn!("remove log file failed: {}", e));
        })?;
        let pid = child.id().unwrap();
        *self.pid.lock().unwrap() = Some(pid);
        resume_as_user(pid, &self.username, &self.token);
        Ok(child)
    }

    pub async fn run(self: &Arc<Self>) -> Result<()> {
        info!("=>WindowsCommand::run()");
        self.store_path_check()?;
        self.work_dir_check()?;

        let (our_pipe, their_pipe) = anon_pipe(true)?;
        let log_file = self.open_log_file().await?;
        let mut child = self.spawn_cmd(their_pipe)?;
        let base = self.clone();

        // async read output.
        info!("=>WindowsCommand::tokio::spawn");
        tokio::spawn(async move {
            let reader = tokio::fs::File::from_std(our_pipe);
            base.read_output(reader, log_file).await;
            base.process_finish(&mut child).await;
        });
        Ok(())
    }
}

pub fn init_powershell_cmd(script: &str) -> Command {
    let mut cmd = Command::new("powershell");
    cmd.args(&[
        "-ExecutionPolicy",
        "Bypass",
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;",
        &script,
    ]);
    cmd
}

pub fn init_bat_cmd(script: &str) -> Command {
    let mut cmd = Command::new("cmd.exe");
    cmd.args(&["/C", script]);
    cmd
}

pub fn prepare_cmd(
    mut cmd: Command,
    username: &str,
    work_dir: &str,
    pipe: File,
) -> Result<Command> {
    let std_out = pipe
        .try_clone()
        .inspect_err(|e| error!("prepare_cmd, clone pipe std_out failed: {}", e))?;
    let std_err = pipe
        .try_clone()
        .inspect_err(|e| error!("prepare_cmd, clone pipe std_err failed: {}", e))?;
    cmd.stdin(Stdio::null())
        .stdout(std_out)
        .stderr(std_err)
        .current_dir(work_dir)
        .creation_flags(CREATE_SUSPENDED); //create as suspend
    if !get_current_username().eq_ignore_ascii_case(username) {
        let token = get_user_token(username)?;
        let envs = load_environment(token.as_raw_handle());
        cmd.env_clear().envs(envs);
    }
    Ok(cmd)
}

pub fn resume_as_user(pid: u32, username: &str, token: &File) {
    unsafe {
        let process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        let current_user = get_current_username();
        if !current_user.eq_ignore_ascii_case(username) {
            let mut access_token = PROCESS_ACCESS_TOKEN {
                Token: token.as_raw_handle(),
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

pub fn kill_process_group(pid: u32) {
    info!("=>kill_process_group, pid:{}", pid);
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
            if index == child_pids.len() {
                break;
            }
            for (_, (ppid, pid)) in proc_list.iter().enumerate() {
                if *ppid == *child_pids.get(index).unwrap() {
                    child_pids.push(*pid);
                }
            }
            index = index + 1;
        }

        //kill process
        for (_, pid) in child_pids.iter().enumerate() {
            info!("pid need to kill: {}", pid);
            let handle = OpenProcess(PROCESS_TERMINATE, FALSE, *pid);
            if handle != NULL {
                TerminateProcess(handle, 0xffffffff as u32);
                CloseHandle(handle);
            } else {
                error!("open pid error: {}", GetLastError());
            }
        }
    }
}

pub fn anon_pipe(ours_readable: bool) -> Result<(File, File)> {
    unsafe {
        let mut tries = 0;
        let mut name;
        let ours: File;
        loop {
            tries += 1;
            name = format!(
                r"\\.\pipe\__tat_anon_pipe__.{}.{}",
                GetCurrentProcessId(),
                gen_rand_str_with(10)
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
                error!("create namepipe failed: {}", err);
                return Err(anyhow!("create namepipe failed: {}", err));
            }
            ours = File::from_raw_handle(handle);
            break;
        }

        let mut opts = OpenOptions::new();
        opts.write(ours_readable);
        opts.read(!ours_readable);

        let theirs = opts.open(Path::new(&name))?;
        Ok((ours, theirs))
    }
}

pub fn load_environment(token: HANDLE) -> HashMap<String, String> {
    unsafe {
        let mut envs = HashMap::new();
        let mut environment: PVOID = null_mut();
        if 0 != CreateEnvironmentBlock(&mut environment as *mut LPVOID, token, FALSE) {
            // The total size len * mem::size_of::<T>() of the slice must be no larger than isize::MAX
            // See doc: https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html
            let data = slice::from_raw_parts(
                environment as *const u16,
                isize::MAX as usize / mem::size_of::<u16>(),
            );
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
        envs
    }
}

fn create_user_token(user_name: &str) -> Result<File> {
    info!("=>enter create_user_token");
    unsafe {
        let mut tat_name = "tat".to_string();
        let mut tat_lsa = LSA_STRING {
            Length: tat_name.len() as USHORT,
            MaximumLength: tat_name.len() as USHORT,
            Buffer: tat_name.as_mut_ptr() as PCHAR,
        };

        let mut lsa_handle = 0 as HANDLE;
        let mut mode: LSA_OPERATIONAL_MODE = mem::zeroed();
        let code = LsaRegisterLogonProcess(&mut tat_lsa as PLSA_STRING, &mut lsa_handle, &mut mode);
        if code != 0 {
            return Err(anyhow!("RegisterLogonProcess Failed: {}", code));
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

        let domain_buffer = name_buffer.add(wname_size);
        let wdomain = str2wsz(".");
        let wdomain_size = (wdomain.len() - 1) * 2;
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
            wdomain_size,
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

        let status = LsaLogonUser(
            lsa_handle,
            &mut tat_lsa,
            3,
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
            return Err(anyhow!("LsaLogonUser Failed, {}", status));
        }

        let _token = File::from_raw_handle(token);
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
            Err(anyhow!("DuplicateTokenEx Failed, {}", GetLastError()))
        };
    }
}

pub fn get_user_token(user_name: &str) -> Result<File> {
    static IS_2008: LazyLock<bool> = LazyLock::new(|| {
        let output = std::process::Command::new("wmic")
            .args(&["os", "get", "Caption"])
            .stdout(Stdio::piped())
            .output()
            .unwrap();
        let version = String::from_utf8_lossy(&output.stdout)
            .escape_debug()
            .to_string();
        info!("OS version: {}", version);
        version.contains("2008")
    });

    if get_current_username().eq_ignore_ascii_case(user_name) || *IS_2008 {
        info!(
            "use current token, user:{}, is_2008:{}",
            user_name, *IS_2008
        );
        let mut token: HANDLE = 0 as HANDLE;
        unsafe {
            if 0 == OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token) {
                return Err(anyhow!("OpenProcessToken Failed: {}", GetLastError()));
            }
            return Ok(File::from_raw_handle(token));
        }
    }
    create_user_token(user_name)
}

pub fn decode_output(v: &[u8]) -> Vec<u8> {
    static CODEPAGE: LazyLock<u16> = LazyLock::new(|| unsafe { GetOEMCP() } as u16);

    match std::str::from_utf8(&v) {
        Ok(output) => output.into(),
        Err(_) => codepage_strings::Coding::new(*CODEPAGE)
            .expect("create decoder failed")
            .decode(&v)
            .expect("output_string decode failed"),
    }
    .into_owned()
    .into_bytes()
}

#[cfg(test)]
mod test {
    use crate::executor::windows::anon_pipe;
    use std::io::{Read, Write};
    #[test]
    fn test() {
        let (mut ours, mut theirs) = anon_pipe(true).unwrap();
        theirs.write("test".as_bytes()).unwrap();
        let mut buffer = [0; 1024];
        let size = ours.read(&mut buffer).unwrap();
        let result = String::from_utf8_lossy(&buffer[0..size]);
        assert_eq!(result, "test".to_string());
    }
}
