use crate::common::consts::{
    FS_TYPE_DIR, FS_TYPE_FILE, FS_TYPE_LINK, PTY_BIN_MSG, PTY_INSPECT_READ, PTY_INSPECT_WRITE,
    SLOT_PTY_BIN, WS_MSG_TYPE_CREATE_FILE, WS_MSG_TYPE_PTY_DELETE_FILE, WS_MSG_TYPE_PTY_EXEC_CMD,
    WS_MSG_TYPE_PTY_FILE_EXIST, WS_MSG_TYPE_PTY_FILE_INFO, WS_MSG_TYPE_PTY_LIST_PATH,
    WS_MSG_TYPE_PTY_READ_FILE, WS_MSG_TYPE_PTY_WRITE_FILE,
};

use super::PtySession;
use crate::common::evbus::EventBus;
use crate::conpty::thread::SessionManager;
use crate::types::ws_msg::{
    CreateFileReq, CreateFileResp, DeleteFileReq, DeleteFileResp, ExecCmdReq, FileExistResp,
    FileExistsReq, FileInfoReq, FileInfoResp, ListPathReq, ListPathResp, PtyBinBase, PtyBinErrResp,
    ReadFileReq, ReadFileResp, WriteFileReq, WriteFileResp, WsMsg,
};
use bson::Document;
use glob::Pattern;
use log::info;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fs::File;
use std::fs::Metadata;
use std::fs::{self, create_dir_all};
use std::io::Cursor;
use std::io::SeekFrom::Start;
use std::io::{Read, Seek, Write};
use std::path::Path;
use std::sync::atomic::Ordering::SeqCst;
use std::sync::Arc;
use std::time::SystemTime;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use winapi::um::winnt::FILE_ATTRIBUTE_HIDDEN;
        use crate::common::strwsz::str2wsz;
        use winapi::um::fileapi::{GetDriveTypeW, GetLogicalDrives};
        use winapi::um::winbase::DRIVE_FIXED;
        use crate::common::consts::FS_TYPE_PARTITION;
        use std::os::windows::fs::MetadataExt;
    }
    else if #[cfg(unix)] {
        use std::process::{Command, Stdio};
        use procfs::process::Process;
        use std::os::unix::process::CommandExt;
        use std::os::linux::fs::MetadataExt;
        use std::os::unix::prelude::PermissionsExt;
        use users::get_user_by_uid;
        use users::get_group_by_gid;
        use chrono::Local;
        use chrono::DateTime;
        use crate::types::ws_msg::ExecCmdResp;
    }
}

pub(crate) fn register_pty_bin_handlers(smgr: Arc<SessionManager>) {
    let self_0 = smgr.clone();
    let self_1 = smgr.clone();
    let self_2 = smgr.clone();
    let self_3 = smgr.clone();
    let self_4 = smgr.clone();
    let self_5 = smgr.clone();
    let self_6 = smgr.clone();
    let self_7 = smgr.clone();

    smgr.event_bus
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_CREATE_FILE, move |msg| {
            self_0.work_as_user_flow(
                msg,
                WS_MSG_TYPE_CREATE_FILE,
                SessionManager::pty_create_file,
            );
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_DELETE_FILE, move |msg| {
            self_1.work_as_user_flow(
                msg,
                WS_MSG_TYPE_PTY_DELETE_FILE,
                SessionManager::pty_delete_file,
            );
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_LIST_PATH, move |msg| {
            self_2.simple_flow(
                msg,
                WS_MSG_TYPE_PTY_LIST_PATH,
                SessionManager::pty_list_path,
            );
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_FILE_EXIST, move |msg| {
            self_3.work_as_user_flow(
                msg,
                WS_MSG_TYPE_PTY_FILE_EXIST,
                SessionManager::pty_file_exists,
            );
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_FILE_INFO, move |msg| {
            self_4.work_as_user_flow(
                msg,
                WS_MSG_TYPE_PTY_FILE_INFO,
                SessionManager::pty_file_info,
            );
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_WRITE_FILE, move |msg| {
            self_5.simple_flow(
                msg,
                WS_MSG_TYPE_PTY_WRITE_FILE,
                SessionManager::pty_write_file,
            )
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_READ_FILE, move |msg| {
            self_6.simple_flow(
                msg,
                WS_MSG_TYPE_PTY_READ_FILE,
                SessionManager::pty_read_file,
            )
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_EXEC_CMD, move |msg| {
            self_7.work_as_user_flow(msg, WS_MSG_TYPE_PTY_EXEC_CMD, SessionManager::pty_exec);
        });
}

struct Context<T> {
    session_id: String,
    op: String,
    seq: u64,
    req: PtyBinBase<T>,
    session: Arc<dyn PtySession + Sync + Send>,
    event_bus: Arc<EventBus>,
}

impl SessionManager {
    fn work_as_user_flow<'a, T, F>(&self, msg: Vec<u8>, op: &str, func: F)
    where
        F: Fn(&SessionManager, Arc<Context<T>>) -> Result<Vec<u8>, String> + 'static + Sync + Send,
        T: DeserializeOwned + Default + Sync + Send + 'static,
    {
        match Document::from_reader(&mut Cursor::new(&msg[..])) {
            Ok(doc) => {
                let req = match bson::from_document::<PtyBinBase<T>>(doc) {
                    Ok(req) => req,
                    Err(e) => {
                        log::error!("work_as_user_flow from_document fail {}", e.to_string());
                        return;
                    }
                };

                if let Some(session) = self.check_session(&req.session_id) {
                    let context = Arc::new(Context {
                        session_id: req.session_id.clone(),
                        op: op.to_string(),
                        seq: self.ws_seq_num.fetch_add(1, SeqCst),
                        req,
                        session: session.pty_session.clone(),
                        event_bus: self.event_bus.clone(),
                    });

                    let self_0 = self.clone();
                    let result = session
                        .pty_session
                        .work_as_user(Box::new(move || func(&self_0, context.clone())))
                        .unwrap();

                    self.event_bus.dispatch(PTY_BIN_MSG, result);
                };
            }
            Err(e) => {
                log::error!("work_as_user_flow from_reader fail {}", e.to_string())
            }
        };
    }

    fn simple_flow<'a, T, F>(&self, msg: Vec<u8>, op: &str, func: F)
    where
        F: Fn(&SessionManager, Arc<Context<T>>) + 'static + Sync + Send,
        T: DeserializeOwned + Default + Sync + Send + 'static,
    {
        match Document::from_reader(&mut Cursor::new(&msg[..])) {
            Ok(doc) => {
                let req = match bson::from_document::<PtyBinBase<T>>(doc) {
                    Ok(req) => req,
                    Err(e) => {
                        log::error!("simple_flow from_document fail {}", e.to_string());
                        return;
                    }
                };

                if let Some(session) = self.check_session(&req.session_id) {
                    let context = Arc::new(Context {
                        session_id: req.session_id.clone(),
                        op: op.to_string(),
                        seq: self.ws_seq_num.fetch_add(1, SeqCst),
                        req,
                        session: session.pty_session.clone(),
                        event_bus: self.event_bus.clone(),
                    });

                    func(&self, context);
                };
            }
            Err(e) => {
                log::error!("simple_flow from_reader fail {}", e.to_string())
            }
        };
    }

    fn pty_create_file(&self, context: Arc<Context<CreateFileReq>>) -> Result<Vec<u8>, String> {
        info!("=>{} pty_create_file", context.session_id);
        let param = &context.req.data;
        if Path::new(&param.path).exists() && !param.overwrite {
            return Ok(build_ptybin_error(context, "file exsits"));
        }

        let parrent_path = Path::new(&param.path).parent();
        if parrent_path.is_none() {
            return Ok(build_ptybin_error(context, "invalid path"));
        }

        return match create_dir_all(parrent_path.unwrap()) {
            Ok(_) => match File::create(&param.path) {
                Ok(_file) => {
                    #[cfg(unix)]
                    _file.metadata().unwrap().permissions().set_mode(param.mode);
                    Ok(build_ptybin_result(
                        context,
                        CreateFileResp { created: true },
                    ))
                }
                Err(e) => Ok(build_ptybin_error(context, &e.to_string())),
            },
            Err(e) => Ok(build_ptybin_error(context, &e.to_string())),
        };
    }

    fn pty_delete_file(&self, context: Arc<Context<DeleteFileReq>>) -> Result<Vec<u8>, String> {
        info!("=>{} pty_delete_file", context.session_id);
        let param = &context.req.data;
        return match fs::remove_file(param.path.clone()) {
            Ok(_) => Ok(build_ptybin_result(
                context,
                DeleteFileResp { deleted: true },
            )),
            Err(e) => Ok(build_ptybin_error(context, &e.to_string())),
        };
    }

    fn pty_list_path(&self, context: Arc<Context<ListPathReq>>) {
        info!(
            "=>{} pty_list_path path {} filter {}",
            context.session_id, context.req.data.path, context.req.data.filter
        );

        let pattern = match Pattern::new(&context.req.data.filter) {
            Ok(pattern) => pattern,
            Err(e) => {
                return context.event_bus.dispatch(
                    PTY_BIN_MSG,
                    build_ptybin_error(context.clone(), &e.to_string()),
                )
            }
        };

        //list path as user
        let context_0 = context.clone();
        let files = match context.session.work_as_user(Box::new(move || {
            let files = list_path(&context_0.req.data.path, pattern.clone())?;
            let mut result = Vec::new();
            let obj = bson::to_bson(&files).unwrap();
            let mut doc = Document::new();
            doc.insert("files", obj);
            let _ = doc.to_writer(&mut result);
            Ok(result)
        })) {
            Ok(output) => {
                let doc = Document::from_reader(&mut Cursor::new(&output[..])).unwrap();
                let files = bson::from_bson::<Vec<FileInfoResp>>(doc.get("files").unwrap().clone())
                    .unwrap();
                files
            }
            Err(err_msg) => {
                return context
                    .event_bus
                    .dispatch(PTY_BIN_MSG, build_ptybin_error(context.clone(), &err_msg))
            }
        };

        //server limit one packet 4KB, one FileInfoResp about 250 kb, so send 10 files each packet
        let mut remain = &files[..];
        let mut index = 0;
        let mut is_last = false;
        loop {
            let items;
            if remain.len() > 10 {
                (items, remain) = remain.split_at(10);
            } else {
                items = remain;
                is_last = true;
            }

            context.event_bus.dispatch(
                PTY_BIN_MSG,
                build_ptybin_result(
                    context.clone(),
                    ListPathResp {
                        index,
                        is_last,
                        files: items.to_vec(),
                    },
                ),
            );

            index = index + 1;
            if is_last {
                break;
            }
        }
    }

    fn pty_file_exists(&self, context: Arc<Context<FileExistsReq>>) -> Result<Vec<u8>, String> {
        info!("=>{} pty_file_exists", context.session_id);
        let param = &context.req.data;
        let exists = Path::exists(param.path.as_ref());
        let data = FileExistResp { exists };
        Ok(build_ptybin_result(context, data))
    }

    fn pty_file_info(&self, context: Arc<Context<FileInfoReq>>) -> Result<Vec<u8>, String> {
        info!("=>{} pty_file_info", context.session_id);
        let param = &context.req.data;
        return match fs::metadata(&param.path) {
            Ok(meta_data) => {
                let info = file_info_data(param.path.clone(), &meta_data);
                Ok(build_ptybin_result(context, info))
            }
            Err(e) => Ok(build_ptybin_error(context, &e.to_string())),
        };
    }

    fn pty_write_file(&self, context: Arc<Context<WriteFileReq>>) {
        let param = &context.req.data;

        //check permssion
        if let Err(err_msg) = context
            .session
            .inspect_access(&param.path, PTY_INSPECT_WRITE)
        {
            return context
                .event_bus
                .dispatch(PTY_BIN_MSG, build_ptybin_error(context.clone(), &err_msg));
        };

        let mut file = match fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(&param.path)
        {
            Ok(file) => file,
            Err(e) => {
                return context.event_bus.dispatch(
                    PTY_BIN_MSG,
                    build_ptybin_error(context.clone(), &e.to_string()),
                );
            }
        };

        if param.offset != usize::MAX {
            if let Err(e) = file.seek(Start(param.offset as u64)) {
                return context.event_bus.dispatch(
                    PTY_BIN_MSG,
                    build_ptybin_error(context.clone(), &e.to_string()),
                );
            };
        }

        return match file.write(&param.data) {
            Ok(length) => context.event_bus.dispatch(
                PTY_BIN_MSG,
                build_ptybin_result(context.clone(), WriteFileResp { length }),
            ),
            Err(e) => context.event_bus.dispatch(
                PTY_BIN_MSG,
                build_ptybin_error(context.clone(), &e.to_string()),
            ),
        };
    }

    fn pty_read_file(&self, context: Arc<Context<ReadFileReq>>) {
        info!("=>{} pty_read_file", context.session_id);
        let param = &context.req.data;
        //check permssion
        if let Err(err_msg) = context
            .session
            .inspect_access(&param.path, PTY_INSPECT_READ)
        {
            info!("=>{} inspect_access fail", context.session_id);
            return context
                .event_bus
                .dispatch(PTY_BIN_MSG, build_ptybin_error(context.clone(), &err_msg));
        };

        //open file read only
        let mut file = match File::open(&param.path) {
            Ok(file) => file,
            Err(e) => {
                return context.event_bus.dispatch(
                    PTY_BIN_MSG,
                    build_ptybin_error(context.clone(), &e.to_string()),
                );
            }
        };

        if let Err(e) = file.seek(Start(param.offset as u64)) {
            return context.event_bus.dispatch(
                PTY_BIN_MSG,
                build_ptybin_error(context.clone(), &e.to_string()),
            );
        };

        let mut left = param.size;
        let mut buffer: [u8; 3072] = [0; 3072];
        let mut offset = param.offset;
        loop {
            let len = std::cmp::min(left, 3072);
            if len == 0 {
                break;
            }
            let size_r = file.read(&mut buffer[0..len]);
            match size_r {
                Ok(size) => {
                    if size > 0 {
                        left = left - size;
                        let is_last = left == 0 || size < len;
                        let rsp = ReadFileResp {
                            data: buffer[0..size].to_owned(),
                            offset,
                            length: size,
                            is_last,
                        };
                        offset = offset + size;
                        context
                            .event_bus
                            .dispatch(PTY_BIN_MSG, build_ptybin_result(context.clone(), rsp));
                        if is_last {
                            break;
                        }
                    } else {
                        let rsp = ReadFileResp {
                            data: vec![],
                            offset,
                            length: 0,
                            is_last: true,
                        };
                        context
                            .event_bus
                            .dispatch(PTY_BIN_MSG, build_ptybin_result(context.clone(), rsp));
                        break;
                    }
                }
                Err(e) => {
                    context.event_bus.dispatch(
                        PTY_BIN_MSG,
                        build_ptybin_error(context.clone(), &e.to_string()),
                    );
                    break;
                }
            };
        }
    }

    fn pty_exec(&self, context: Arc<Context<ExecCmdReq>>) -> Result<Vec<u8>, String> {
        #[cfg(unix)]
        unsafe {
            let param = &context.req.data;
            let cmd = param.cmd.clone();
            let pid = context.session.get_pid().unwrap();
            let process = Process::new(pid as i32).unwrap();

            let output = Command::new("bash")
                .args(&["-c", cmd.as_str()])
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .current_dir(process.cwd().unwrap())
                .pre_exec(|| {
                    libc::dup2(1, 2);
                    Ok(())
                })
                .output()
                .unwrap();
            let output = String::from_utf8_lossy(&output.stdout);
            let data = ExecCmdResp {
                output: output.to_string(),
            };
            return Ok(build_ptybin_result(context, data));
        }
        #[cfg(windows)]
        Ok(build_ptybin_error(context, "not support on windows"))
    }
}

fn build_ptybin_result<Req, Resp>(context: Arc<Context<Req>>, data: Resp) -> Vec<u8>
where
    Resp: Serialize,
{
    let ws_msg = WsMsg::<PtyBinBase<Resp>> {
        r#type: context.op.clone(),
        seq: context.seq,
        data: Some(PtyBinBase::<Resp> {
            session_id: context.req.session_id.clone(),
            custom_data: context.req.custom_data.clone(),
            data,
        }),
    };

    let mut result = Vec::new();
    let obj = bson::to_bson(&ws_msg).unwrap();
    let doc = obj.as_document().unwrap();
    let _ = doc.to_writer(&mut result);
    result
}

fn build_ptybin_error<Req>(context: Arc<Context<Req>>, error: &str) -> Vec<u8> {
    // Vec::new()
    let ws_msg = WsMsg::<PtyBinBase<PtyBinErrResp>> {
        r#type: context.op.clone(),
        seq: context.seq,
        data: Some(PtyBinBase::<PtyBinErrResp> {
            session_id: context.req.session_id.clone(),
            custom_data: context.req.custom_data.clone(),
            data: PtyBinErrResp {
                error: error.to_string(),
            },
        }),
    };

    let mut result = Vec::new();
    let obj = bson::to_bson(&ws_msg).unwrap();
    let doc = obj.as_document().unwrap();
    let _ = doc.to_writer(&mut result);
    result
}

#[cfg(windows)]
fn get_win32_ready_drives() -> Vec<String> {
    unsafe {
        let mut logical_drives = Vec::new();
        let mut driver_bit = GetLogicalDrives();
        let mut label_base = 'A';
        while driver_bit != 0 {
            if driver_bit & 1 == 1 {
                let disk_label = label_base.to_string() + ":/";
                let disk_type = GetDriveTypeW(str2wsz(&disk_label).as_ptr());
                if disk_type == DRIVE_FIXED {
                    logical_drives.push(disk_label);
                }
            }
            label_base = std::char::from_u32((label_base as u32) + 1).unwrap();
            driver_bit >>= 1;
        }
        logical_drives
    }
}

//windows path format:  /d:/work
fn list_path(path: &str, filter: Pattern) -> Result<Vec<FileInfoResp>, String> {
    let mut files = Vec::<FileInfoResp>::new();
    let mut path = path.to_string();
    #[cfg(windows)]
    {
        if path == "/" {
            let disks = get_win32_ready_drives();
            for disk in disks {
                files.push(FileInfoResp {
                    r#type: FS_TYPE_PARTITION.to_string(),
                    name: disk,
                    size: 0,
                    modify_time: 0,
                    access_time: 0,
                })
            }
            return Ok(files);
        }
    }

    if std::env::consts::OS == "windows" && path.starts_with("/") {
        path = path[1..].to_string();
    }

    let items = fs::read_dir(path).map_err(|e| e.to_string())?;
    for item in items {
        if let Ok(entry) = item {
            let name = entry.file_name().to_string_lossy().to_string();
            if !filter.matches(&name) {
                continue;
            }
            if let Ok(meta_data) = entry.metadata() {
                #[cfg(windows)]
                {
                    let attr = meta_data.file_attributes();
                    if attr & FILE_ATTRIBUTE_HIDDEN != 0 {
                        continue;
                    }
                }
                files.push(file_info_data(name, &meta_data))
            }
        }
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    return Ok(files);
}

fn file_info_data(name: String, meta_data: &Metadata) -> FileInfoResp {
    let fs_type = if meta_data.is_dir() {
        FS_TYPE_DIR.to_string()
    } else if meta_data.is_symlink() {
        FS_TYPE_LINK.to_string()
    } else {
        FS_TYPE_FILE.to_string()
    };

    FileInfoResp {
        r#type: fs_type,
        name: name.clone(),
        size: meta_data.len(),
        modify_time: meta_data
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        access_time: meta_data
            .accessed()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        #[cfg(unix)]
        owner: meta_data.st_uid(),
        #[cfg(unix)]
        group: meta_data.st_gid(),
        #[cfg(unix)]
        rights: unix_mode::to_string(meta_data.permissions().mode()),
        #[cfg(unix)]
        longname: get_long_name(name, &meta_data),
    }
}

#[cfg(unix)]
fn get_long_name(name: String, meta_data: &Metadata) -> String {
    let rights = unix_mode::to_string(meta_data.permissions().mode());
    let link_count = meta_data.st_nlink();

    let owner_name = if let Some(user) = get_user_by_uid(meta_data.st_uid()) {
        user.name().to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };

    let group_name = if let Some(group) = get_group_by_gid(meta_data.st_gid()) {
        group.name().to_string_lossy().to_string()
    } else {
        "unknown".to_string()
    };
    let size = meta_data.st_size();

    let datetime: DateTime<Local> = meta_data.modified().unwrap().into();
    let time = format!("{}", datetime.format("%b %d %R"));

    let longname = format!(
        "{} {} {} {} {} {} {}",
        rights, link_count, owner_name, group_name, size, time, name
    );
    return longname;
}

#[cfg(test)]
mod test {

    use std::{
        collections::HashMap,
        fs::{self, File},
        io::Cursor,
        path::Path,
        process::Stdio,
        sync::{atomic::AtomicU64, Arc, Mutex, RwLock},
    };

    use crate::{
        common::{
            consts::{
                PTY_BIN_MSG, WS_MSG_TYPE_CREATE_FILE, WS_MSG_TYPE_PTY_DELETE_FILE,
                WS_MSG_TYPE_PTY_READ_FILE, WS_MSG_TYPE_PTY_WRITE_FILE,
            },
            evbus::EventBus,
            logger::init_test_log,
        },
        conpty::{
            ptybin::{list_path, Context},
            thread::SessionManager,
            PtySession,
        },
        types::ws_msg::{
            CreateFileReq, DeleteFileReq, PtyBinBase, ReadFileReq, ReadFileResp, WriteFileReq,
        },
    };

    use log::info;
    use crate::types::ws_msg::WsMsg;
    use bson::Document;
    use glob::Pattern;
    use rand::{distributions::Alphanumeric, thread_rng, Rng};

    const SESSION_ID: &str = "x-xxxxxxxxx";

    fn get_temp_file_path() -> String {
        format!(
            "/tmp/{}",
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(5)
                .collect::<String>()
        )
    }

    fn random_vec(len: usize) -> Vec<u8> {
        let random_string = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(len)
            .collect::<String>();
        return Vec::from(random_string.as_bytes());
    }

    #[derive(Default)]
    struct MockPtySesssion {}

    impl PtySession for MockPtySesssion {
        fn resize(&self, _cols: u16, _rows: u16) -> Result<(), String> {
            todo!()
        }

        fn get_reader(&self) -> Result<File, String> {
            todo!()
        }

        fn get_writer(&self) -> Result<File, String> {
            todo!()
        }

        fn get_pid(&self) -> Result<u32, String> {
            todo!()
        }

        fn work_as_user(&self, func: crate::conpty::Handler) -> Result<Vec<u8>, String> {
            return Ok(func().unwrap());
        }

        fn inspect_access(&self, _path: &str, _access: u8) -> Result<(), String> {
            Ok(())
        }
    }

    #[test]
    fn test_create_delete() {
        let fake_seesion_mgr = SessionManager {
            ws_seq_num: Arc::new(AtomicU64::new(0)),
            running_task_num: Arc::new(AtomicU64::new(0)),
            session_map: Arc::new(RwLock::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new()),
        };

        let temp_path = get_temp_file_path();
        let context = Arc::new(Context::<CreateFileReq> {
            session_id: SESSION_ID.to_owned(),
            op: WS_MSG_TYPE_CREATE_FILE.to_owned(),
            seq: 0,
            req: PtyBinBase {
                session_id: SESSION_ID.to_owned(),
                custom_data: "".to_string(),
                data: CreateFileReq {
                    path: temp_path.clone(),
                    mode: 0o644,
                    overwrite: true,
                },
            },
            session: Arc::new(MockPtySesssion::default()),
            event_bus: Arc::new(EventBus::new()),
        });
        fake_seesion_mgr.pty_create_file(context).unwrap();
        let exist = Path::exists(temp_path.as_ref());
        assert!(exist);

        let context = Arc::new(Context::<DeleteFileReq> {
            session_id: SESSION_ID.to_owned(),
            op: WS_MSG_TYPE_PTY_DELETE_FILE.to_owned(),
            seq: 0,
            req: PtyBinBase {
                session_id: SESSION_ID.to_owned(),
                custom_data: "".to_string(),
                data: DeleteFileReq {
                    path: temp_path.clone(),
                },
            },
            session: Arc::new(MockPtySesssion::default()),
            event_bus: Arc::new(EventBus::new()),
        });
        fake_seesion_mgr.pty_delete_file(context).unwrap();
        let exist = Path::exists(temp_path.as_ref());
        assert!(!exist);
    }

    #[test]
    fn test_write_read() {
        let fake_seesion_mgr = SessionManager {
            ws_seq_num: Arc::new(AtomicU64::new(0)),
            running_task_num: Arc::new(AtomicU64::new(0)),
            session_map: Arc::new(RwLock::new(HashMap::new())),
            event_bus: Arc::new(EventBus::new()),
        };

        let temp_path = get_temp_file_path();
        File::create(temp_path.clone()).unwrap();

        let test_data = random_vec(100);

        let context = Arc::new(Context::<WriteFileReq> {
            session_id: SESSION_ID.to_owned(),
            op: WS_MSG_TYPE_PTY_WRITE_FILE.to_owned(),
            seq: 0,
            req: PtyBinBase {
                session_id: SESSION_ID.to_owned(),
                custom_data: "".to_string(),
                data: WriteFileReq {
                    path: temp_path.clone(),
                    offset: 0,
                    data: test_data.clone(),
                },
            },
            session: Arc::new(MockPtySesssion::default()),
            event_bus: Arc::new(EventBus::new()),
        });
        fake_seesion_mgr.pty_write_file(context);

        let context = Arc::new(Context::<ReadFileReq> {
            session_id: SESSION_ID.to_owned(),
            op: WS_MSG_TYPE_PTY_READ_FILE.to_owned(),
            seq: 0,
            req: PtyBinBase {
                session_id: SESSION_ID.to_owned(),
                custom_data: "".to_string(),
                data: ReadFileReq {
                    path: temp_path.clone(),
                    offset: 0,
                    size: 100,
                },
            },
            session: Arc::new(MockPtySesssion::default()),
            event_bus: Arc::new(EventBus::new()),
        });

        let (msg_sender, msg_receiver) = std::sync::mpsc::channel::<PtyBinBase<ReadFileResp>>();
        let msg_sender_holder = Arc::new(Mutex::new(msg_sender));

        context.event_bus.register(PTY_BIN_MSG, move |data| {
            let doc = Document::from_reader(&mut Cursor::new(&data[..])).unwrap();
            let ws_msg = bson::from_document::<WsMsg<PtyBinBase<ReadFileResp>>>(doc).unwrap();
            let resp = ws_msg.data.unwrap();
            let _ = msg_sender_holder.lock().unwrap().send(resp);
        });

        fake_seesion_mgr.pty_read_file(context);
        let _ = fs::remove_file(temp_path);
        let resp = msg_receiver.recv().unwrap();
        assert_eq!(resp.data.is_last, true);
        assert_eq!(resp.data.length, 100);
        assert_eq!(resp.data.data, test_data);
    }

    #[test]
    fn test_list() {
        #[cfg(windows)]
        let path = "/C:/Program Files";
        #[cfg(unix)]
        let path = "/usr/local/bin/";

        init_test_log();
        let pattern = Pattern::new("*").unwrap();
        let files = list_path(path, pattern).unwrap();

        #[cfg(windows)]
        let std_output = {
            let cmd_win = "@echo off \r\n dir /b \"C:\\Program Files\" | find /v /c \"::\"";
            let _ = fs::write("count_files.bat", cmd_win.as_bytes());
            let std_output = std::process::Command::new(".\\count_files.bat")
                .stdout(Stdio::piped())
                .output();
            fs::remove_file(".\\count_files.bat").unwrap();
            std_output.unwrap()
        };

        #[cfg(unix)]
        let std_output = {
            std::process::Command::new("sh")
                .args(["-c", "ls /usr/local/bin/ |wc -l"])
                .stdout(Stdio::piped())
                .output()
                .unwrap()
        };

        let output = String::from_utf8_lossy(&std_output.stdout);
        let my_int = output.trim().parse::<usize>().unwrap();

        info!("my_int {},files.len {}", my_int, files.len());
        assert_eq!(my_int, files.len());
        return;
    }
}
