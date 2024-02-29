use super::gather::PtyGather;
use super::handler::{BsonHandler, Handler};
use crate::common::evbus::EventBus;
use crate::network::types::ws_msg::{
    CreateFileReq, CreateFileResp, DeleteFileReq, DeleteFileResp, FileExistResp, FileExistsReq,
    FileInfoReq, FileInfoResp, ListPathReq, ListPathResp, PtyBinErrMsg, ReadFileReq, ReadFileResp,
    WriteFileReq, WriteFileResp,
};

use std::fs::{self, create_dir_all, File, Metadata};
use std::io::{Seek, SeekFrom::Start, Write};
use std::iter::{once, repeat};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use glob::Pattern;
use log::info;
use tokio::io::AsyncReadExt;

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use crate::common::utils::str2wsz;
        use std::os::windows::fs::MetadataExt;
        use winapi::um::winnt::FILE_ATTRIBUTE_HIDDEN;
        use winapi::um::fileapi::{GetDriveTypeW, GetLogicalDrives};
        use winapi::um::winbase::DRIVE_FIXED;
        const FS_TYPE_PARTITION: &str = "p";
    }
    else if #[cfg(unix)] {
        use std::os::linux::fs::MetadataExt;
        use std::os::unix::prelude::PermissionsExt;
        use users::get_user_by_uid;
        use users::get_group_by_gid;
        use chrono::Local;
        use chrono::DateTime;
    }
}

use super::{PTY_INSPECT_READ, PTY_INSPECT_WRITE, SLOT_PTY_BIN};
const FS_TYPE_FILE: &str = "-";
const FS_TYPE_DIR: &str = "d";
const FS_TYPE_LINK: &str = "l";
const WS_MSG_TYPE_PTY_LIST_PATH: &str = "PtyListPath";
const WS_MSG_TYPE_PTY_FILE_EXIST: &str = "PtyFileExist";
const WS_MSG_TYPE_PTY_CREATE_FILE: &str = "PtyCreateFile";
const WS_MSG_TYPE_PTY_DELETE_FILE: &str = "PtyDeleteFile";
const WS_MSG_TYPE_PTY_READ_FILE: &str = "PtyReadFile";
const WS_MSG_TYPE_PTY_WRITE_FILE: &str = "PtyWriteFile";
const WS_MSG_TYPE_PTY_FILE_INFO: &str = "PtyFileInfo";

pub fn register_file_handlers(event_bus: &Arc<EventBus>) {
    event_bus
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_CREATE_FILE, move |msg| {
            BsonHandler::<CreateFileReq>::dispatch(msg)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_DELETE_FILE, move |msg| {
            BsonHandler::<DeleteFileReq>::dispatch(msg)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_LIST_PATH, move |msg| {
            BsonHandler::<ListPathReq>::dispatch(msg)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_FILE_EXIST, move |msg| {
            BsonHandler::<FileExistsReq>::dispatch(msg)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_FILE_INFO, move |msg| {
            BsonHandler::<FileInfoReq>::dispatch(msg)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_WRITE_FILE, move |msg| {
            BsonHandler::<WriteFileReq>::dispatch(msg)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_READ_FILE, move |msg| {
            BsonHandler::<ReadFileReq>::dispatch(msg)
        });
}

impl Handler for BsonHandler<CreateFileReq> {
    fn process(self) {
        let session_id = self.request.session_id.clone();
        let req_data = &self.request.data;

        info!("=>{} pty_create_file", session_id);
        if Path::new(&req_data.path).exists() && !req_data.overwrite {
            return self.reply(PtyBinErrMsg::new("file exists"));
        }
        let Some(parent_path) = Path::new(&req_data.path).parent() else {
            return self.reply(PtyBinErrMsg::new("invalid path"));
        };

        //create file as user
        let create_result = self.associate_pty.execute(&|| -> Result<Vec<u8>, String> {
            create_dir_all(parent_path).map_err(|e| e.to_string())?;
            let _file = File::create(&req_data.path).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            if let Ok(meta) = _file.metadata() {
                meta.permissions().set_mode(req_data.mode);
            }
            Ok(Vec::new())
        });

        match create_result {
            Ok(_) => self.reply(CreateFileResp { created: true }),
            Err(e) => self.reply(PtyBinErrMsg::new(e)),
        }
    }
}

impl Handler for BsonHandler<DeleteFileReq> {
    fn process(self) {
        let session_id = self.request.session_id.clone();
        let req_data = &self.request.data;

        if let Err(e) = self
            .associate_pty
            .inspect_access(&req_data.path, PTY_INSPECT_WRITE)
        {
            return self.reply(PtyBinErrMsg::new(e));
        }

        info!("=>{} pty_delete_file", session_id);
        match fs::remove_file(req_data.path.clone()) {
            Ok(_) => self.reply(DeleteFileResp { deleted: true }),
            Err(e) => self.reply(PtyBinErrMsg::new(e)),
        };
    }
}

impl Handler for BsonHandler<ListPathReq> {
    fn process(self) {
        let session_id = self.request.session_id.clone();
        let req_data = &self.request.data;

        info!(
            "=>{} pty_list_path path {} filter {}",
            session_id, req_data.path, req_data.filter
        );

        let pattern = match Pattern::new(&req_data.filter) {
            Ok(pattern) => pattern,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)),
        };

        let files = match list_path(&req_data.path, pattern.clone()) {
            Ok(files) => files,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)),
        };

        files
            .chunks(10)
            .zip(repeat(false))
            .chain(once((vec![].as_slice(), true)))
            .zip(0u32..)
            .for_each(|((items, is_last), index)| {
                self.reply(ListPathResp {
                    index,
                    is_last,
                    files: items.to_vec(),
                })
            });
    }
}

impl Handler for BsonHandler<FileExistsReq> {
    fn process(self) {
        let session_id = self.request.session_id.clone();
        let req_data = &self.request.data;
        info!("=>{} pty_file_exists", session_id);
        let exists = Path::exists(req_data.path.as_ref());
        return self.reply(FileExistResp { exists });
    }
}

impl Handler for BsonHandler<FileInfoReq> {
    fn process(self) {
        let session_id = self.request.session_id.clone();
        let req_data = &self.request.data;
        info!("=>{} pty_file_info", session_id);
        match fs::metadata(&req_data.path) {
            Ok(meta_data) => self.reply(file_info_data(req_data.path.clone(), &meta_data)),
            Err(e) => self.reply(PtyBinErrMsg::new(e)),
        };
    }
}

impl Handler for BsonHandler<WriteFileReq> {
    fn process(self) {
        let req_data = &self.request.data;
        //check permission
        if let Err(err_msg) = self
            .associate_pty
            .inspect_access(&req_data.path, PTY_INSPECT_WRITE)
        {
            return self.reply(PtyBinErrMsg::new(err_msg));
        };

        let mut file = match fs::OpenOptions::new()
            .write(true)
            .append(true)
            .open(&req_data.path)
        {
            Ok(file) => file,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)),
        };

        if req_data.offset != usize::MAX {
            if let Err(e) = file.seek(Start(req_data.offset as u64)) {
                return self.reply(PtyBinErrMsg::new(e));
            };
        }

        match file.write(&req_data.data) {
            Ok(length) => self.reply(WriteFileResp { length }),
            Err(e) => self.reply(PtyBinErrMsg::new(e)),
        };
    }
}

//read
impl BsonHandler<ReadFileReq> {
    async fn async_read(self_: Arc<Self>) {
        let session_id = self_.request.session_id.clone();
        let param = &self_.request.data;
        info!("=>{} ReadFileReq {}", session_id, param.path);
        //check permission
        if let Err(err_msg) = self_
            .associate_pty
            .inspect_access(&param.path, PTY_INSPECT_READ)
        {
            info!("=>{} inspect_access failed", session_id);
            return self_.reply(PtyBinErrMsg::new(err_msg));
        };

        //open file read only
        let mut file = match File::open(&param.path) {
            Ok(file) => file,
            Err(e) => return self_.reply(PtyBinErrMsg::new(e)),
        };

        if let Err(e) = file.seek(Start(param.offset as u64)) {
            return self_.reply(PtyBinErrMsg::new(e));
        };

        //use async file
        let mut file = tokio::fs::File::from_std(file);
        let mut remainder = param.size;
        let mut offset = param.offset;
        let mut buffer: [u8; 3072] = [0; 3072];
        loop {
            let upper_limit = std::cmp::min(remainder, 3072);
            match file.read(&mut buffer[..upper_limit]).await {
                Ok(size) => {
                    remainder -= size;
                    let is_last = remainder == 0 || size < upper_limit;
                    self_.reply(ReadFileResp {
                        data: buffer[..size].to_owned(),
                        offset,
                        length: size,
                        is_last,
                    });
                    if is_last {
                        break;
                    }
                    offset += size;
                }
                Err(e) => break self_.reply(PtyBinErrMsg::new(e)),
            };
        }
    }
}

impl Handler for BsonHandler<ReadFileReq> {
    fn process(self) {
        let self_0 = Arc::new(self);
        PtyGather::runtime().spawn(async move {
            BsonHandler::<ReadFileReq>::async_read(self_0).await;
        });
    }
}

#[cfg(windows)]
fn get_win32_ready_drives() -> Vec<String> {
    let mut logical_drives = Vec::new();
    let mut driver_bit = unsafe { GetLogicalDrives() };
    let mut label_base = 'A';
    while driver_bit != 0 {
        if driver_bit & 1 == 1 {
            let disk_label = label_base.to_string() + ":/";
            let disk_type = unsafe { GetDriveTypeW(str2wsz(&disk_label).as_ptr()) };
            if disk_type == DRIVE_FIXED {
                logical_drives.push(disk_label);
            }
        }
        label_base = std::char::from_u32((label_base as u32) + 1).expect("invalid char");
        driver_bit >>= 1;
    }
    logical_drives
}

//windows path format:  /d:/work
fn list_path(path: &str, filter: Pattern) -> Result<Vec<FileInfoResp>, String> {
    let mut files = Vec::<FileInfoResp>::new();
    let mut path = path.to_string();

    #[cfg(windows)]
    if path == "/" {
        for name in get_win32_ready_drives() {
            files.push(FileInfoResp {
                r#type: FS_TYPE_PARTITION.to_string(),
                name,
                size: 0,
                modify_time: 0,
                access_time: 0,
            })
        }
        return Ok(files);
    }

    if std::env::consts::OS == "windows" && path.starts_with("/") {
        path = path[1..].to_string();
    }

    let items = fs::read_dir(path).map_err(|e| e.to_string())?;
    for item in items {
        let Ok(entry) = item else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if !filter.matches(&name) {
            continue;
        }
        if let Ok(meta_data) = entry.metadata() {
            #[cfg(windows)]
            if meta_data.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0 {
                continue;
            }
            files.push(file_info_data(name, &meta_data))
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

    let owner_name = match get_user_by_uid(meta_data.st_uid()) {
        Some(user) => user.name().to_string_lossy().to_string(),
        None => "unknown".to_string(),
    };
    let group_name = match get_group_by_gid(meta_data.st_gid()) {
        Some(group) => group.name().to_string_lossy().to_string(),
        None => "unknown".to_string(),
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
    //!todo
}
