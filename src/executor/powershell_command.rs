use crate::daemonizer::wow64_disable_exc;
use crate::executor::proc::{BaseCommand, MyCommand};
use crate::start_failed_err_info;
use async_trait::async_trait;
use codepage_strings::Coding;
use core::mem;
use log::{debug, error, info, warn};
use ntapi::ntpsapi::{
    NtResumeProcess, NtSetInformationProcess, ProcessAccessToken, PROCESS_ACCESS_TOKEN,
};
use ntapi::ntrtl::{RtlAdjustPrivilege, RtlFreeSid, RtlLengthSid};
use ntapi::ntseapi::{NtCreateToken, SE_ASSIGNPRIMARYTOKEN_PRIVILEGE, SE_CREATE_TOKEN_PRIVILEGE};
use ntapi::winapi::shared::ntdef::TRUE;
use ntapi::winapi::um::winnt::{SE_GROUP_INTEGRITY, SE_GROUP_INTEGRITY_ENABLED};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fmt::{Debug, Formatter};
use std::fs::{remove_file, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::prelude::OsStringExt;
use std::path::Path;
use std::process::Stdio;
use std::ptr::null_mut;
use std::sync::Arc;
use std::{fmt, slice};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use winapi::shared::lmcons::MAX_PREFERRED_LENGTH;
use winapi::shared::minwindef::{DWORD, FALSE, LPBYTE, LPDWORD, LPVOID, ULONG};
use winapi::shared::ntdef::{
    BOOLEAN, CHAR, LARGE_INTEGER, LPCWSTR, LPWSTR, LUID, NULL, OBJECT_ATTRIBUTES, PHANDLE,
    PLARGE_INTEGER, PLUID, POBJECT_ATTRIBUTES, PVOID,
};
use winapi::shared::sddl::ConvertStringSidToSidW;
use winapi::shared::winerror::{ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::lmaccess::{
    NetUserGetGroups, NetUserGetLocalGroups, GROUP_USERS_INFO_0, LG_INCLUDE_INDIRECT,
    LOCALGROUP_USERS_INFO_0,
};
use winapi::um::lmapibuf::NetApiBufferFree;
use winapi::um::lsalookup::{LSA_OBJECT_ATTRIBUTES, PLSA_OBJECT_ATTRIBUTES, PLSA_UNICODE_STRING};
use winapi::um::namedpipeapi::CreateNamedPipeW;
use winapi::um::ntlsa::{
    LsaClose, LsaEnumerateAccountRights, LsaFreeMemory, LsaOpenPolicy, LSA_HANDLE,
    POLICY_ALL_ACCESS,
};
use winapi::um::ntsecapi::PLSA_HANDLE;
use winapi::um::processthreadsapi::{
    GetCurrentProcess, GetCurrentProcessId, OpenProcess, OpenProcessToken, TerminateProcess,
};
use winapi::um::securitybaseapi::GetTokenInformation;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, LPPROCESSENTRY32, PROCESSENTRY32,
    TH32CS_SNAPPROCESS,
};
use winapi::um::userenv::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use winapi::um::winbase::{
    GetUserNameW, LookupAccountNameW, LookupPrivilegeValueW, CREATE_NO_WINDOW, CREATE_SUSPENDED,
    FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, PIPE_ACCESS_INBOUND, PIPE_ACCESS_OUTBOUND,
    PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};

use winapi::um::winnls::GetOEMCP;
use winapi::um::winnt::{
    SecurityDelegation, TokenPrimary, TokenStatistics, ANONYMOUS_LOGON_LUID, HANDLE,
    LUID_AND_ATTRIBUTES, PROCESS_ALL_ACCESS, PSID, PTOKEN_DEFAULT_DACL, PTOKEN_GROUPS,
    PTOKEN_OWNER, PTOKEN_PRIMARY_GROUP, PTOKEN_PRIVILEGES, PTOKEN_SOURCE, PTOKEN_USER,
    SECURITY_DYNAMIC_TRACKING, SECURITY_QUALITY_OF_SERVICE, SE_CHANGE_NOTIFY_NAME,
    SE_CREATE_GLOBAL_NAME, SE_GROUP_ENABLED, SE_GROUP_ENABLED_BY_DEFAULT, SE_GROUP_MANDATORY,
    SE_GROUP_OWNER, SE_IMPERSONATE_NAME, SE_PRIVILEGE_ENABLED, SE_PRIVILEGE_ENABLED_BY_DEFAULT,
    SE_PRIVILEGE_REMOVED, SID_AND_ATTRIBUTES, SID_NAME_USE, TOKEN_ALL_ACCESS, TOKEN_GROUPS,
    TOKEN_INFORMATION_CLASS, TOKEN_PRIMARY_GROUP, TOKEN_PRIVILEGES, TOKEN_SOURCE, TOKEN_STATISTICS,
    TOKEN_USER,
};

pub struct PowerShellCommand {
    base: Arc<BaseCommand>,
    token: usize,
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
            token: 0,
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

        let mut command = Command::new("PowerShell.exe");
        command
            .args(&["-ExecutionPolicy", "Bypass", self.base.cmd_path.as_str()])
            .stdin(Stdio::null())
            .stdout(std_out)
            .stderr(std_err)
            .current_dir(self.base.work_dir.as_str())
            .creation_flags(CREATE_SUSPENDED | CREATE_NO_WINDOW); //create as suspend

        let mut envs = HashMap::<String, String>::new();
        if !get_current_user().eq_ignore_ascii_case(&self.base.username) {
            self.token = create_user_token(&self.base.username).map_err(|err| {
                *self.base.err_info.lock().unwrap() = err.clone();
                err
            })? as usize;

            load_environment(self.token as HANDLE, &mut envs);
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
                    Token: self.token as HANDLE,
                    Thread: 0 as HANDLE,
                };
                let status = NtSetInformationProcess(
                    process,
                    ProcessAccessToken,
                    &mut access_token as *mut PROCESS_ACCESS_TOKEN as PVOID,
                    mem::size_of::<PROCESS_ACCESS_TOKEN>() as u32,
                );
                info!("NtSetInformationProcess result is {}", status);
                CloseHandle(self.token as HANDLE);
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
        let pid = self.pid.lock().unwrap().unwrap();
        const BUF_SIZE: usize = 1024;
        let mut buffer: [u8; BUF_SIZE] = [0; BUF_SIZE];

        let mut file = tokio::fs::File::from_std(file);
        let codepage = unsafe { GetOEMCP() };
        loop {
            let size = file.read(&mut buffer[..]).await;
            if size.is_err() {
                error!("read output err:{}, pid:{}", size.unwrap_err(), pid);
                break;
            }
            let len = size.unwrap();
            if len > 0 {
                let decoded_string = Coding::new(codepage as u16)
                    .unwrap()
                    .decode(&buffer[..len])
                    .unwrap();
                debug!("output:[{}], pid:{}, len:{}", decoded_string, pid, len);
                if let Err(e) = log_file.write(decoded_string.as_bytes()) {
                    error!("write output file fail: {:?}", e)
                }
                unsafe {
                    self.append_output(String::from(decoded_string).as_mut_vec());
                }
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
            child_pids.push(pid);
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
                let handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, *pid);
                if handle != NULL {
                    TerminateProcess(handle, 0xffffffff as u32);
                    CloseHandle(handle);
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

fn anon_pipe(ours_readable: bool) -> Result<(File, File), String> {
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
            ours = mem::transmute::<HANDLE, File>(handle);
            break;
        }

        let mut opts = OpenOptions::new();
        opts.write(ours_readable);
        opts.read(!ours_readable);

        let theirs = opts.open(Path::new(&name)).map_err(|e| e.to_string())?;
        Ok((ours, theirs))
    }
}

fn wsz2string(ptr: *const u16) -> String {
    use std::ffi::OsString;
    unsafe {
        let len = (0..std::isize::MAX)
            .position(|i| *ptr.offset(i) == 0)
            .unwrap();
        let slice = std::slice::from_raw_parts(ptr, len);
        OsString::from_wide(slice).to_string_lossy().into_owned()
    }
}

fn str2wsz(s: &str) -> Vec<u16> {
    OsStr::new(s)
        .encode_wide()
        .chain(Some(0).into_iter())
        .collect::<Vec<_>>()
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

fn get_user_sid(user_name: &str) -> Result<Vec<u8>, String> {
    info!("=>enter get_user_sid");
    unsafe {
        let wsz_name = str2wsz(user_name);

        let mut sid_size: u32 = 0;
        let mut sid_buffer: Vec<u8> = Vec::new();

        let mut domain_size: u32 = 0;
        let mut domain_buffer: Vec<u8> = Vec::new();

        let mut sid_type: SID_NAME_USE = mem::zeroed();

        LookupAccountNameW(
            NULL as LPCWSTR,
            wsz_name.as_ptr(),
            sid_buffer.as_ptr() as PSID,
            &mut sid_size as LPDWORD,
            domain_buffer.as_ptr() as LPCWSTR,
            &mut domain_size as LPDWORD,
            &mut sid_type as *mut SID_NAME_USE,
        );
        if GetLastError() != ERROR_INSUFFICIENT_BUFFER {
            error!("get_user_sid fail {}", GetLastError());
            return Err(format!("User {} Not Exist", user_name));
        }

        sid_buffer.resize(sid_size as usize, 0);
        domain_buffer.resize((domain_size * 2) as usize, 0);

        if 0 != LookupAccountNameW(
            NULL as LPCWSTR,
            wsz_name.as_ptr(),
            sid_buffer.as_ptr() as PSID,
            &mut sid_size as LPDWORD,
            domain_buffer.as_ptr() as LPCWSTR,
            &mut domain_size as LPDWORD,
            &mut sid_type as *mut SID_NAME_USE,
        ) {
            return Ok(sid_buffer);
        };
        error!("get_user_sid fail {}", GetLastError());
        return Err(format!("User {} Not Exist", user_name));
    }
}

fn create_user_token(user_name: &str) -> Result<HANDLE, String> {
    info!("=>enter create_user_token");
    unsafe {
        let user_sid = get_user_sid(user_name)?;
        let mut token: HANDLE = 0 as HANDLE;
        let mut sqos = SECURITY_QUALITY_OF_SERVICE {
            Length: mem::size_of::<SECURITY_QUALITY_OF_SERVICE>() as u32,
            ImpersonationLevel: SecurityDelegation,
            ContextTrackingMode: SECURITY_DYNAMIC_TRACKING,
            EffectiveOnly: 0,
        };

        let mut oa: OBJECT_ATTRIBUTES = mem::zeroed();
        oa.Length = mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
        oa.SecurityQualityOfService = &mut sqos as *mut SECURITY_QUALITY_OF_SERVICE as PVOID;

        let mut auth_id = get_auth_id();

        let mut exptm: LARGE_INTEGER = mem::transmute(0xffffffffffffffff as u64);

        let mut token_user = TOKEN_USER {
            User: SID_AND_ATTRIBUTES {
                Sid: user_sid.as_ptr() as PSID,
                Attributes: 0,
            },
        };

        let token_groups_data = get_user_token_groups(user_name);
        let token_groups = token_groups_data.as_ptr() as PTOKEN_GROUPS;

        let privileges_data = get_user_privileges(user_name);
        let privileges = privileges_data.as_ptr() as PTOKEN_PRIVILEGES;

        let mut primary_group = TOKEN_PRIMARY_GROUP {
            PrimaryGroup: user_sid.as_ptr() as PSID,
        };

        let mut token_source = TOKEN_SOURCE {
            SourceName: [
                'T' as CHAR,
                'A' as CHAR,
                'T' as CHAR,
                'S' as CHAR,
                'V' as CHAR,
                'C' as CHAR,
                0 as CHAR,
                0 as CHAR,
            ],
            SourceIdentifier: mem::zeroed(),
        };

        let status = NtCreateToken(
            &mut token as PHANDLE,
            TOKEN_ALL_ACCESS,
            &mut oa as POBJECT_ATTRIBUTES,
            TokenPrimary,
            &mut auth_id as PLUID,
            &mut exptm as PLARGE_INTEGER,
            &mut token_user as PTOKEN_USER,
            token_groups as PTOKEN_GROUPS,
            privileges,
            NULL as PTOKEN_OWNER,
            &mut primary_group as PTOKEN_PRIMARY_GROUP,
            NULL as PTOKEN_DEFAULT_DACL,
            &mut token_source as PTOKEN_SOURCE,
        );
        if status != 0 {
            error!("create_user_token fail,err is {}", status);
            return Err(format!("CreateUserToken Fail,Err:{}", status));
        }
        info!("create_user_token sucess");
        Ok(token)
    }
}

fn get_auth_id() -> LUID {
    unsafe {
        static mut IS_2008: Option<bool> = None;
        let is_2008 = IS_2008.get_or_insert_with(|| {
            //only execute once
            let output = std::process::Command::new("wmic")
                .args(&["os", "get", "Caption"])
                .stdout(Stdio::piped())
                .output()
                .unwrap();
            let version = String::from_utf8_lossy(&output.stdout);
            info!("version is {}", version);
            let result = version.contains("2008");
            result
        });

        return if *is_2008 {
            ANONYMOUS_LOGON_LUID
        } else {
            let mut base_token: HANDLE = 0 as HANDLE;
            OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_ALL_ACCESS,
                &mut base_token as PHANDLE,
            );
            let token_static_data = get_token_info(base_token, TokenStatistics).unwrap();
            let toeken_static = token_static_data.as_ptr() as *mut TOKEN_STATISTICS;
            CloseHandle(base_token);
            (*toeken_static).AuthenticationId
        };
    }
}

fn conver_to_sid(sid_name: &str) -> Vec<u8> {
    let buffer_data = Vec::<u8>::new();
    let mut writer = BufWriter::new(buffer_data);
    let mut psid: PSID = null_mut();
    let wsz_sid = str2wsz(sid_name);
    unsafe {
        ConvertStringSidToSidW(wsz_sid.as_ptr(), &mut psid);
        writer
            .write(slice::from_raw_parts(
                psid as *const u8,
                RtlLengthSid(psid as PSID) as usize,
            ))
            .unwrap();
        RtlFreeSid(psid);
        writer.buffer().to_vec()
    }
}

fn common_user_group_attrs(user_name: &str) -> Vec<(Vec<u8>, DWORD)> {
    let attr = SE_GROUP_ENABLED | SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT;
    let mut group_sid_attrs = Vec::<(Vec<u8>, DWORD)>::new();
    //Everyone
    group_sid_attrs.push((conver_to_sid("S-1-1-0"), attr));
    //Users
    group_sid_attrs.push((conver_to_sid("S-1-5-32-545"), attr));
    //NT AUTHORITY\NETWORK
    group_sid_attrs.push((conver_to_sid("S-1-5-2"), attr));
    //NT AUTHORITY\Authenticated Users
    group_sid_attrs.push((conver_to_sid("S-1-5-11"), attr));
    //NT AUTHORITY\This Organization
    group_sid_attrs.push((conver_to_sid("S-1-5-15"), attr));
    //NT AUTHORITY\Local account
    group_sid_attrs.push((conver_to_sid("S-1-5-113"), attr));
    //NT AUTHORITY\NTLM Authentication
    group_sid_attrs.push((conver_to_sid("S-1-5-64-10"), attr));
    //Mandatory Label\High Mandatory Level
    group_sid_attrs.push((
        conver_to_sid("S-1-16-12288"),
        SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED,
    ));

    let user_groups = get_user_groups(user_name);
    for (_, group) in user_groups.iter().enumerate() {
        if group.eq("Administrators") {
            // BUILTIN\Administrators
            group_sid_attrs.push((conver_to_sid("S-1-5-32-544"), attr | SE_GROUP_OWNER));
            // NT AUTHORITY\Local account and member of Administrators group
            group_sid_attrs.push((conver_to_sid("S-1-5-114"), attr));
        } else {
            let sid_data = get_user_sid(group).unwrap();
            group_sid_attrs.push((sid_data, attr));
        }
    }
    return group_sid_attrs;
}

fn system_user_group_attrs() -> Vec<(Vec<u8>, DWORD)> {
    let attr = SE_GROUP_ENABLED | SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT;
    let mut group_sid_attrs = Vec::<(Vec<u8>, DWORD)>::new();
    //NT AUTHORITY\Authenticated Users
    group_sid_attrs.push((conver_to_sid("S-1-5-11"), attr));
    //Everyone
    group_sid_attrs.push((conver_to_sid("S-1-1-0"), attr));
    //BUILTIN\Administrators
    group_sid_attrs.push((conver_to_sid("S-1-5-32-544"), attr | SE_GROUP_OWNER));
    //Mandatory Label\System Mandatory Level
    group_sid_attrs.push((
        conver_to_sid("S-1-16-16384"),
        SE_GROUP_INTEGRITY | SE_GROUP_INTEGRITY_ENABLED,
    ));
    return group_sid_attrs;
}

fn get_user_token_groups(user_name: &str) -> Vec<u8> {
    unsafe {
        let group_offset: usize =
            field_offset::offset_of!(TOKEN_GROUPS => Groups).get_byte_offset();

        let buffer_data = Vec::<u8>::new();
        let mut writer = BufWriter::new(buffer_data);
        let count: u64 = 0; //correct this value later
        writer
            .write(slice::from_raw_parts(
                &count as *const u64 as *const u8,
                group_offset,
            ))
            .unwrap();

        //build all groups strs
        let group_sid_attrs;
        if user_name.eq_ignore_ascii_case("System") {
            group_sid_attrs = system_user_group_attrs();
        } else {
            group_sid_attrs = common_user_group_attrs(user_name);
        }

        //write sid_and_attribute to the buffer
        for i in 0..group_sid_attrs.len() {
            let template = SID_AND_ATTRIBUTES {
                Sid: NULL as PSID, //correct this value later
                Attributes: group_sid_attrs.get(i).unwrap().1,
            };
            writer
                .write(slice::from_raw_parts(
                    &template as *const SID_AND_ATTRIBUTES as *const u8,
                    mem::size_of::<SID_AND_ATTRIBUTES>(),
                ))
                .unwrap();
        }

        //write sid to the buffer
        for (_, sid_attr) in group_sid_attrs.iter().enumerate() {
            writer
                .write(slice::from_raw_parts(
                    sid_attr.0.as_ptr() as *const u8,
                    RtlLengthSid(sid_attr.0.as_ptr() as PSID) as usize,
                ))
                .unwrap();
        }
        let mut token_groups_data = writer.buffer().to_vec();

        //correct count
        *(token_groups_data[0..3].as_mut_ptr() as *mut u32) = group_sid_attrs.len() as u32;

        //get slice of groups
        let mut sid_and_attrs = slice::from_raw_parts_mut::<SID_AND_ATTRIBUTES>(
            (token_groups_data[group_offset..]).as_ptr() as *mut SID_AND_ATTRIBUTES,
            group_sid_attrs.len(),
        );

        //correct sid value in sid_and_attrs
        let mut psid_offset =
            group_offset + group_sid_attrs.len() * mem::size_of::<SID_AND_ATTRIBUTES>();
        let mut psid_position = token_groups_data[psid_offset as usize..].as_ptr();
        for i in 0..group_sid_attrs.len() {
            sid_and_attrs[i].Sid = psid_position as PSID;
            psid_offset = psid_offset + RtlLengthSid(psid_position as PSID) as usize;
            psid_position = token_groups_data[psid_offset..].as_ptr();
        }
        return token_groups_data;
    };
}

fn get_user_privileges(user: &str) -> Vec<u8> {
    let buffer_data = Vec::<u8>::new();
    let mut writer = BufWriter::new(buffer_data);
    unsafe {
        let privileges_offset: usize =
            field_offset::offset_of!(TOKEN_PRIVILEGES => Privileges).get_byte_offset();

        let mut lsa_handle = 0 as LSA_HANDLE;
        let mut lsa_attr: LSA_OBJECT_ATTRIBUTES = mem::zeroed();

        LsaOpenPolicy(
            NULL as PLSA_UNICODE_STRING,
            &mut lsa_attr as PLSA_OBJECT_ATTRIBUTES, //Object attributes.
            POLICY_ALL_ACCESS,                       //Desired access permissions.
            &mut lsa_handle as *const LSA_HANDLE as PLSA_HANDLE,
        );

        let mut right_set_temp = HashSet::<String>::new();
        let mut groups = Vec::<String>::new();
        groups.push(user.to_string());
        if user.eq_ignore_ascii_case("System") {
            groups.push("Administrators".to_string());
        } else {
            groups = get_user_groups(user);
        }

        for (_, group) in groups.iter().enumerate() {
            let sid = get_user_sid(group).unwrap();
            let mut buffer: PLSA_UNICODE_STRING = null_mut();
            let mut count = 0 as ULONG;
            LsaEnumerateAccountRights(lsa_handle, sid.as_ptr() as PSID, &mut buffer, &mut count);
            if 0 != count {
                let slice = slice::from_raw_parts(buffer, count as usize);
                for i in 0..count as usize {
                    let szdata = slice::from_raw_parts(
                        slice[i].Buffer as *const u16,
                        (slice[i].Length / 2) as usize,
                    );

                    let right = wsz2string(szdata.as_ptr());
                    if !right.ends_with("Privilege") {
                        continue;
                    }
                    right_set_temp.insert(right);
                }
                LsaFreeMemory(buffer as PVOID);
            }
        }
        LsaClose(lsa_handle);
        let count: u64 = right_set_temp.len() as u64;
        writer
            .write(slice::from_raw_parts(
                &count as *const u64 as *const u8,
                privileges_offset,
            ))
            .unwrap();

        for (_, right) in right_set_temp.iter().enumerate() {
            let wsz_right = str2wsz(right);
            let mut luid: LUID = mem::zeroed();
            LookupPrivilegeValueW(NULL as LPCWSTR, wsz_right.as_ptr(), &mut luid);

            let mut attr = SE_PRIVILEGE_REMOVED;
            if right.eq(SE_CHANGE_NOTIFY_NAME)
                || right.eq(SE_CREATE_GLOBAL_NAME)
                || right.eq(SE_IMPERSONATE_NAME)
            {
                attr |= SE_PRIVILEGE_ENABLED | SE_PRIVILEGE_ENABLED_BY_DEFAULT;
            }
            let la = LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: attr,
            };
            writer
                .write(slice::from_raw_parts(
                    &la as *const LUID_AND_ATTRIBUTES as *const u8,
                    mem::size_of::<LUID_AND_ATTRIBUTES>(),
                ))
                .unwrap();
        }

        let token_privileges = writer.buffer().to_vec();
        return token_privileges;
    }
}

fn get_user_groups(user_name: &str) -> Vec<String> {
    let mut result = Vec::<String>::new();
    let wsz_user = str2wsz(user_name);
    unsafe {
        let mut buffer: LPBYTE = null_mut();
        let mut entries = 0;
        let mut total_entries = 0;
        NetUserGetLocalGroups(
            NULL as LPCWSTR,
            wsz_user.as_ptr(),
            0,
            LG_INCLUDE_INDIRECT,
            &mut buffer as *mut LPBYTE,
            MAX_PREFERRED_LENGTH,
            &mut entries,
            &mut total_entries,
        );

        let group_slice =
            slice::from_raw_parts(buffer as *const LOCALGROUP_USERS_INFO_0, entries as usize);
        for i in 0..entries as usize {
            let group_name = wsz2string(group_slice[i].lgrui0_name);
            result.push(group_name);
        }
        NetApiBufferFree(buffer as LPVOID);
    }

    unsafe {
        let mut buffer: LPBYTE = null_mut();
        let mut entries = 0;
        let mut total_entries = 0;
        NetUserGetGroups(
            NULL as LPCWSTR,
            wsz_user.as_ptr(),
            0,
            &mut buffer as *mut LPBYTE,
            MAX_PREFERRED_LENGTH,
            &mut entries,
            &mut total_entries,
        );
        let group_slice = slice::from_raw_parts::<GROUP_USERS_INFO_0>(
            buffer as *const GROUP_USERS_INFO_0,
            entries as usize,
        );
        for i in 0..entries as usize {
            let group_name = wsz2string(group_slice[i].grui0_name);
            result.push(group_name);
        }
        NetApiBufferFree(buffer as LPVOID);
    }
    result
}

fn load_environment(token: HANDLE, envs: &mut HashMap<String, String>) {
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

pub fn get_token_info(
    token: HANDLE,
    info_type: TOKEN_INFORMATION_CLASS,
) -> Result<Vec<u8>, String> {
    unsafe {
        let mut len: u32 = 0;
        if FALSE == GetTokenInformation(token, info_type, NULL as PVOID, 0, &mut len as LPDWORD)
            && GetLastError() != ERROR_INSUFFICIENT_BUFFER
        {
            return Err(format!("GetTokenInformation fail {}", GetLastError()));
        }
        let mut data: Vec<u8> = Vec::new();
        data.resize(len as usize, 0);
        GetTokenInformation(
            token,
            info_type,
            data.as_ptr() as LPVOID,
            len,
            &mut len as LPDWORD,
        );
        return Ok(data);
    }
}

pub fn adjust_privileage() {
    let mut enabled: BOOLEAN = FALSE as u8;
    unsafe {
        RtlAdjustPrivilege(
            SE_ASSIGNPRIMARYTOKEN_PRIVILEGE as u32,
            TRUE,
            FALSE as u8,
            &mut enabled,
        );
        RtlAdjustPrivilege(
            SE_CREATE_TOKEN_PRIVILEGE as u32,
            TRUE,
            FALSE as u8,
            &mut enabled,
        );
    }
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
