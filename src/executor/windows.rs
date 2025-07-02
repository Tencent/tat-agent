use super::task::{Task, TaskInfo};
use crate::common::{gen_rand_str_with, get_current_username, str2wsz, wsz2string};

use core::str;
use std::collections::HashMap;
use std::fs::{File as StdFile, OpenOptions};
use std::os::windows::prelude::{AsRawHandle, FromRawHandle};
use std::{mem, ptr::null_mut, slice};
use std::{path::Path, process::Stdio};

use anyhow::{bail, Context, Result};
use libc::{c_void, free, malloc, memcpy};
use log::{error, info};
use tokio::fs::{try_exists, File};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};

use ntapi::ntpsapi::{
    NtResumeProcess, NtSetInformationProcess, ProcessAccessToken, PROCESS_ACCESS_TOKEN,
};
use winapi::{
    shared::{
        minwindef::{DWORD, FALSE, LPVOID, ULONG, USHORT},
        ntdef::{LUID, NTSTATUS, NULL, PCHAR, PVOID},
        winerror::ERROR_ACCESS_DENIED,
    },
    um::{
        errhandlingapi::GetLastError,
        handleapi::{CloseHandle, INVALID_HANDLE_VALUE},
        lsalookup::LSA_STRING,
        minwinbase::LPSECURITY_ATTRIBUTES,
        namedpipeapi::CreateNamedPipeW,
        ntlsa::{LsaDeregisterLogonProcess, LsaFreeReturnBuffer, LsaLogonUser},
        ntlsa::{LsaLookupAuthenticationPackage, LsaRegisterLogonProcess, LSA_OPERATIONAL_MODE},
        ntsecapi::{MsV1_0S4ULogon, MSV1_0_S4U_LOGON},
        processthreadsapi::{GetCurrentProcess, GetCurrentProcessId, OpenProcess},
        processthreadsapi::{OpenProcessToken, TerminateProcess},
        securitybaseapi::{AllocateLocallyUniqueId, DuplicateTokenEx},
        subauth::UNICODE_STRING,
        tlhelp32::{CreateToolhelp32Snapshot, Process32First, Process32Next},
        tlhelp32::{LPPROCESSENTRY32, PROCESSENTRY32, TH32CS_SNAPPROCESS},
        userenv::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
        winbase::{CREATE_SUSPENDED, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED},
        winbase::{PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND},
        winbase::{PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT},
        winnt::{RtlZeroMemory, SecurityImpersonation, TokenPrimary, HANDLE, PROCESS_ALL_ACCESS},
        winnt::{PROCESS_TERMINATE, PTOKEN_GROUPS, QUOTA_LIMITS, TOKEN_ALL_ACCESS, TOKEN_SOURCE},
    },
};

pub const UTF8_BOM_HEADER: [u8; 3] = [0xEF, 0xBB, 0xBF];
pub const CMD_TYPE_POWERSHELL: &str = "POWERSHELL";
const CMD_TYPE_BAT: &str = "BAT";
const EXTENSION_BAT: &str = "bat";
const EXTENSION_PS1: &str = "ps1";

pub struct User {
    pub token: File,
    pub is_current: bool,
}

impl Task {
    pub async fn spawn(&mut self) -> Result<(Child, impl AsyncReadExt + Unpin)> {
        let info = &self.info;
        let script = info.script_path()?.into_os_string().into_string().unwrap();
        let mut cmd = if info.command_type == CMD_TYPE_POWERSHELL {
            init_powershell_command(&script.replace(" ", "` "))
        } else {
            init_bat_command(&script)
        };

        let (reader, writer) = unsafe { anon_pipe(true)? };
        configure_command(&mut cmd, &info.user, &info.working_directory, writer).await?;

        let child = cmd.spawn()?;
        unsafe { resume_as_user(child.id().unwrap(), &info.user) };
        Ok((child, reader))
    }
}

impl TaskInfo {
    pub fn script_extension(&self) -> Result<&'static str> {
        let extension = match self.command_type.as_str() {
            CMD_TYPE_BAT => EXTENSION_BAT,
            CMD_TYPE_POWERSHELL => EXTENSION_PS1,
            _ => bail!("invalid `{}` type in Windows.", self.command_type),
        };
        Ok(extension)
    }

    pub async fn check_working_directory(&self) -> Result<()> {
        let dir = &self.working_directory;
        match try_exists(dir).await {
            Ok(exist) if exist => Ok(()),
            Ok(_) => bail!("working_directory `{dir}` not exists"),
            Err(e) => bail!("working_directory `{dir}` check failed: `{e}`"),
        }
    }
}

impl User {
    pub fn new(username: &str) -> Result<Self> {
        let token = unsafe { get_token(username)? };
        let is_current = get_current_username().eq_ignore_ascii_case(username);
        Ok(Self { token, is_current })
    }
}

pub fn init_powershell_command(script: &str) -> Command {
    let mut cmd = Command::new("powershell");
    cmd.args([
        "-ExecutionPolicy",
        "Bypass",
        "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8;",
        script,
    ]);
    cmd
}

pub fn init_bat_command(script: &str) -> Command {
    let mut cmd = Command::new("cmd.exe");
    cmd.args(["/C", script]);
    cmd
}

pub async fn configure_command(
    cmd: &mut Command,
    user: &User,
    work_dir: &str,
    pipe: StdFile,
) -> Result<()> {
    let stdout = pipe.try_clone().context("stdout clone failed")?;
    let stderr = pipe.try_clone().context("stderr clone failed")?;
    cmd.stdin(Stdio::null())
        .stdout(stdout)
        .stderr(stderr)
        .current_dir(work_dir)
        .creation_flags(CREATE_SUSPENDED); //create as suspend
    if !user.is_current {
        let envs = unsafe { load_envs(user.token.as_raw_handle()) };
        cmd.env_clear().envs(envs);
    }
    Ok(())
}

pub unsafe fn resume_as_user(pid: u32, user: &User) {
    let process = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if !user.is_current {
        let mut access_token = PROCESS_ACCESS_TOKEN {
            Token: user.token.as_raw_handle(),
            Thread: 0 as HANDLE,
        };
        let status = NtSetInformationProcess(
            process,
            ProcessAccessToken,
            &raw mut access_token as PVOID,
            mem::size_of::<PROCESS_ACCESS_TOKEN>() as u32,
        );
        info!("NtSetInformationProcess result is {}", status);
    }
    NtResumeProcess(process);
    CloseHandle(process);
}

pub unsafe fn get_token(username: &str) -> Result<File> {
    if get_current_username().eq_ignore_ascii_case(username) {
        info!("use current token, username: {}", username);
        let mut token = 0 as HANDLE;
        if OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &mut token) == 0 {
            bail!("OpenProcessToken failed: {}", GetLastError());
        }
        return Ok(File::from_raw_handle(token));
    }
    create_user_token(username)
}

unsafe fn create_user_token(username: &str) -> Result<File> {
    info!("=>enter create_user_token");

    let mut tat_name = "tat".to_string();
    let mut tat_lsa = LSA_STRING {
        Length: tat_name.len() as USHORT,
        MaximumLength: tat_name.len() as USHORT,
        Buffer: tat_name.as_mut_ptr() as PCHAR,
    };

    let mut lsa_handle = 0 as HANDLE;
    let mut mode: LSA_OPERATIONAL_MODE = mem::zeroed();
    let code = LsaRegisterLogonProcess(&raw mut tat_lsa, &raw mut lsa_handle, &raw mut mode);
    if code != 0 {
        bail!("RegisterLogonProcess failed: {}", code);
    }

    let mut pkg_name = "MICROSOFT_AUTHENTICATION_PACKAGE_V1_0".to_string();
    let mut auth_pkg_name = LSA_STRING {
        Length: pkg_name.len() as USHORT,
        MaximumLength: pkg_name.len() as USHORT,
        Buffer: pkg_name.as_mut_ptr() as PCHAR,
    };

    let mut auth_pkg_id: ULONG = 0;
    LsaLookupAuthenticationPackage(lsa_handle, &raw mut auth_pkg_name, &raw mut auth_pkg_id);

    let logon_info_size = mem::size_of::<MSV1_0_S4U_LOGON>() + (username.len() + ".".len()) * 2;
    let buffer = malloc(logon_info_size);
    RtlZeroMemory(buffer, logon_info_size);

    let s4u_logon = buffer as *mut MSV1_0_S4U_LOGON;
    (*s4u_logon).MessageType = MsV1_0S4ULogon;
    (*s4u_logon).MSV1_0_LOGON_SUBMIT_TYPE = 0;

    let name_buf = buffer.add(mem::size_of::<MSV1_0_S4U_LOGON>());
    let wname = str2wsz(username);
    let wname_size = (wname.len() - 1) * 2;
    memcpy(name_buf, wname.as_ptr() as *const c_void, wname_size);
    (*s4u_logon).UserPrincipalName = UNICODE_STRING {
        Length: wname_size as USHORT,
        MaximumLength: wname_size as USHORT,
        Buffer: name_buf as *mut u16,
    };

    let domain_buf = name_buf.add(wname_size);
    let wdomain = str2wsz(".");
    let wdomain_size = (wdomain.len() - 1) * 2;
    memcpy(domain_buf, wdomain.as_ptr() as *const c_void, wdomain_size);
    (*s4u_logon).DomainName = UNICODE_STRING {
        Length: wdomain_size as USHORT,
        MaximumLength: wdomain_size as USHORT,
        Buffer: domain_buf as *mut u16,
    };

    let mut source_context: TOKEN_SOURCE = mem::zeroed();
    memcpy(
        source_context.SourceName.as_mut_ptr() as *mut c_void,
        tat_name.as_ptr() as *const c_void,
        wdomain_size,
    );
    AllocateLocallyUniqueId(&raw mut source_context.SourceIdentifier);

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
        &raw mut tat_lsa,
        3,
        auth_pkg_id,
        s4u_logon as PVOID,
        logon_info_size as ULONG,
        NULL as PTOKEN_GROUPS,
        &raw mut source_context,
        &raw mut profile,
        &raw mut profile_size,
        &raw mut logon_id,
        &raw mut token,
        &raw mut quotas,
        &raw mut sub_status,
    );

    free(buffer);
    LsaDeregisterLogonProcess(lsa_handle);
    if profile.is_null() {
        LsaFreeReturnBuffer(profile);
    }
    if status != 0 {
        bail!("LsaLogonUser failed: {}", status);
    }

    let token = File::from_raw_handle(token);
    let mut primary_token = 0 as HANDLE;
    DuplicateTokenEx(
        token.as_raw_handle(),
        TOKEN_ALL_ACCESS,
        null_mut() as LPSECURITY_ATTRIBUTES,
        SecurityImpersonation,
        TokenPrimary,
        &raw mut primary_token,
    );
    if primary_token.is_null() {
        bail!("DuplicateTokenEx failed: {}", GetLastError());
    }
    Ok(File::from_raw_handle(primary_token))
}

pub unsafe fn load_envs(token: HANDLE) -> HashMap<String, String> {
    let mut environment: PVOID = null_mut();
    if CreateEnvironmentBlock(&raw mut environment, token, FALSE) == 0 {
        return HashMap::new();
    }
    // The total size len * mem::size_of::<T>() of the slice must be no larger than isize::MAX
    // See doc: https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html
    let data = slice::from_raw_parts(
        environment as *const u16,
        isize::MAX as usize / mem::size_of::<u16>(),
    );
    let envs = data
        .split_inclusive(|c| *c == 0)
        .map(|d| wsz2string(d.as_ptr()))
        .take_while(|s| !s.is_empty())
        .filter_map(|s| s.split_once('=').map(|(k, v)| (k.to_owned(), v.to_owned())))
        .collect();
    DestroyEnvironmentBlock(environment as LPVOID);
    envs
}

pub unsafe fn anon_pipe(ours_readable: bool) -> Result<(File, StdFile)> {
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
            if tries < 10 && err == ERROR_ACCESS_DENIED {
                continue;
            }
            bail!("create namepipe failed: {}", err);
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

pub unsafe fn kill_process_group(pid: u32) {
    info!("=>kill_process_group, pid:{}", pid);

    // get process snapshot
    let hp = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    let mut pe: PROCESSENTRY32 = mem::zeroed();
    pe.dwSize = mem::size_of::<PROCESSENTRY32>() as DWORD;

    let mut snapshot: HashMap<u32, Vec<u32>> = HashMap::new(); // PPID -> PIDs
    let mut code = Process32First(hp, &raw mut pe as LPPROCESSENTRY32);
    while code != 0 {
        let (ppid, pid) = (pe.th32ParentProcessID, pe.th32ProcessID);
        snapshot.entry(ppid).or_default().push(pid);
        code = Process32Next(hp, &raw mut pe as LPPROCESSENTRY32);
    }
    CloseHandle(hp);

    // find all child process
    let mut childs = vec![pid];
    let mut i = 0;
    while i < childs.len() {
        if let Some(pids) = snapshot.get_mut(&childs[i]) {
            childs.append(pids);
        }
        i += 1;
    }

    // kill process
    for pid in childs {
        info!("pid need to kill: {}", pid);
        let handle = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if handle == NULL {
            error!("open pid error: {}", GetLastError());
            continue;
        }
        TerminateProcess(handle, 0xffffffff_u32);
        CloseHandle(handle);
    }
}
