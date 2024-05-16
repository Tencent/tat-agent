use super::handler::{BsonHandler, Handler};
use crate::common::evbus::EventBus;
use crate::network::types::ws_msg::{
    CreateFileReq, CreateFileResp, DeleteFileReq, DeleteFileResp, FileExistResp, FileExistsReq,
    FileInfoReq, FileInfoResp, ListPathReq, ListPathResp, PtyBinErrMsg, ReadFileReq, ReadFileResp,
    WriteFileReq, WriteFileResp,
};

use std::fs::{self, create_dir_all, File, Metadata};
use std::io::{Seek, SeekFrom, Write};
use std::iter::{once, repeat};
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use async_trait::async_trait;
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
            BsonHandler::<CreateFileReq>::dispatch(msg, true)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_DELETE_FILE, move |msg| {
            BsonHandler::<DeleteFileReq>::dispatch(msg, true)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_LIST_PATH, move |msg| {
            BsonHandler::<ListPathReq>::dispatch(msg, true)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_FILE_EXIST, move |msg| {
            BsonHandler::<FileExistsReq>::dispatch(msg, true)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_FILE_INFO, move |msg| {
            BsonHandler::<FileInfoReq>::dispatch(msg, true)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_WRITE_FILE, move |msg| {
            BsonHandler::<WriteFileReq>::dispatch(msg, true)
        })
        .slot_register(SLOT_PTY_BIN, WS_MSG_TYPE_PTY_READ_FILE, move |msg| {
            BsonHandler::<ReadFileReq>::dispatch(msg, true)
        });
}

#[async_trait]
impl Handler for BsonHandler<CreateFileReq> {
    async fn process(self) {
        let data = &self.request.data;
        info!("=>create_file `{}`, path: {}", self.id(), data.path);

        if Path::new(&data.path).exists() && !data.overwrite {
            return self.reply(PtyBinErrMsg::new("file exists"));
        }
        let Some(parent_path) = Path::new(&data.path).parent() else {
            return self.reply(PtyBinErrMsg::new("invalid path"));
        };

        //create file as user
        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        let create_result = plugin.execute(&|| {
            create_dir_all(parent_path).map_err(|e| e.to_string())?;
            let _file = File::create(&data.path).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            if let Ok(meta) = _file.metadata() {
                meta.permissions().set_mode(data.mode);
            }
            Ok(Vec::new())
        });

        match create_result {
            Ok(_) => self.reply(CreateFileResp { created: true }),
            Err(e) => self.reply(PtyBinErrMsg::new(e)),
        }
    }
}

#[async_trait]
impl Handler for BsonHandler<DeleteFileReq> {
    async fn process(self) {
        let path = &self.request.data.path;
        info!("=>delete_file `{}`, path: {}", self.id(), path);

        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        if let Err(e) = plugin.inspect_access(path, PTY_INSPECT_WRITE) {
            return self.reply(PtyBinErrMsg::new(e));
        }

        match fs::remove_file(path) {
            Ok(_) => self.reply(DeleteFileResp { deleted: true }),
            Err(e) => self.reply(PtyBinErrMsg::new(e)),
        };
    }
}

#[async_trait]
impl Handler for BsonHandler<ListPathReq> {
    async fn process(self) {
        let path = &self.request.data.path;
        let filter = &self.request.data.filter;
        let show_hidden = self.request.data.show_hidden;
        let id = self.id();
        info!("=>list_path `{id}`, path: {path}, filter: {filter}",);

        let pattern = match Pattern::new(filter) {
            Ok(pattern) => pattern,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)),
        };

        let files = match list_path(path, pattern.clone(), show_hidden) {
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

#[async_trait]
impl Handler for BsonHandler<FileExistsReq> {
    async fn process(self) {
        let path = &self.request.data.path;
        info!("=>file_exists `{}`, path: {}", self.id(), path);
        let exists = Path::new(path).exists();
        return self.reply(FileExistResp { exists });
    }
}

#[async_trait]
impl Handler for BsonHandler<FileInfoReq> {
    async fn process(self) {
        let path = &self.request.data.path;
        info!("=>file_info `{}`, path: {}", self.id(), path);
        match fs::metadata(path) {
            Ok(metadata) => self.reply(file_info_data(path, &metadata)),
            Err(e) => self.reply(PtyBinErrMsg::new(e)),
        };
    }
}

#[async_trait]
impl Handler for BsonHandler<WriteFileReq> {
    async fn process(self) {
        let data = &self.request.data;
        info!("=>write_file `{}`, path: {}", self.id(), data.path);
        //check permission
        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        if let Err(e) = plugin.inspect_access(&data.path, PTY_INSPECT_WRITE) {
            return self.reply(PtyBinErrMsg::new(e));
        };

        let mut file = match fs::OpenOptions::new().write(true).open(&data.path) {
            Ok(file) => file,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)),
        };

        // Write at the file's end by default if 'offset' is not provided.
        let pos = match data.offset {
            Some(offset) => SeekFrom::Start(offset as u64),
            None => SeekFrom::End(0),
        };

        if let Err(e) = file.seek(pos) {
            return self.reply(PtyBinErrMsg::new(e));
        }

        match file.write(&data.data) {
            Ok(length) => self.reply(WriteFileResp { length }),
            Err(e) => self.reply(PtyBinErrMsg::new(e)),
        };
    }
}

#[async_trait]
impl Handler for BsonHandler<ReadFileReq> {
    async fn process(self) {
        let data = &self.request.data;
        info!("=>read_file `{}`, path: {}", self.id(), data.path);
        //check permission
        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        if let Err(e) = plugin.inspect_access(&data.path, PTY_INSPECT_READ) {
            info!("read_file `{}` inspect_access failed", self.id());
            return self.reply(PtyBinErrMsg::new(e));
        };

        //open file read only
        let mut file = match File::open(&data.path) {
            Ok(file) => file,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)),
        };

        if let Err(e) = file.seek(SeekFrom::Start(data.offset as u64)) {
            return self.reply(PtyBinErrMsg::new(e));
        };

        //use async file
        let mut file = tokio::fs::File::from_std(file);
        let mut remainder = data.size;
        let mut offset = data.offset;
        let mut buffer: [u8; 3072] = [0; 3072];
        loop {
            let upper_limit = std::cmp::min(remainder, 3072);
            match file.read(&mut buffer[..upper_limit]).await {
                Ok(size) => {
                    remainder -= size;
                    let is_last = remainder == 0 || size < upper_limit;
                    self.reply(ReadFileResp {
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
                Err(e) => break self.reply(PtyBinErrMsg::new(e)),
            };
        }
    }
}

#[cfg(windows)]
fn get_win32_ready_drives() -> Vec<String> {
    let driver_bit = unsafe { GetLogicalDrives() };
    ('A'..='Z')
        .enumerate()
        // construct label if the corresponding bit is set
        .filter_map(|(n, lable)| ((driver_bit >> n) & 1 == 1).then(|| format!("{lable}:/")))
        .filter(|l| unsafe { GetDriveTypeW(str2wsz(&l).as_ptr()) } == DRIVE_FIXED)
        .collect()
}

//windows path format:  /d:/work
fn list_path(path: &str, filter: Pattern, show_hidden: bool) -> Result<Vec<FileInfoResp>, String> {
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
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let name = entry.file_name().to_string_lossy().to_string();
        if !show_hidden && is_hidden(&name, &metadata) {
            continue;
        }
        if !filter.matches(&name) {
            continue;
        }
        files.push(file_info_data(&name, &metadata))
    }
    files.sort_by(|a, b| a.name.cmp(&b.name));
    return Ok(files);
}

fn file_info_data(name: &str, metadata: &Metadata) -> FileInfoResp {
    let fs_type = if metadata.is_dir() {
        FS_TYPE_DIR.to_string()
    } else if metadata.is_symlink() {
        FS_TYPE_LINK.to_string()
    } else {
        FS_TYPE_FILE.to_string()
    };

    FileInfoResp {
        r#type: fs_type,
        name: name.to_owned(),
        size: metadata.len(),
        modify_time: metadata
            .modified()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        access_time: metadata
            .accessed()
            .unwrap()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64,
        #[cfg(unix)]
        owner: metadata.st_uid(),
        #[cfg(unix)]
        group: metadata.st_gid(),
        #[cfg(unix)]
        rights: unix_mode::to_string(metadata.permissions().mode()),
        #[cfg(unix)]
        longname: get_long_name(name, &metadata),
    }
}

#[cfg(unix)]
fn get_long_name(name: &str, metadata: &Metadata) -> String {
    let rights = unix_mode::to_string(metadata.permissions().mode());
    let link_count = metadata.st_nlink();

    let owner_name = match get_user_by_uid(metadata.st_uid()) {
        Some(user) => user.name().to_string_lossy().to_string(),
        None => "unknown".to_string(),
    };
    let group_name = match get_group_by_gid(metadata.st_gid()) {
        Some(group) => group.name().to_string_lossy().to_string(),
        None => "unknown".to_string(),
    };
    let size = metadata.st_size();

    let datetime: DateTime<Local> = metadata.modified().unwrap().into();
    let time = format!("{}", datetime.format("%b %d %R"));

    let longname = format!(
        "{} {} {} {} {} {} {}",
        rights, link_count, owner_name, group_name, size, time, name
    );
    return longname;
}

#[cfg(unix)]
fn is_hidden(file_name: &str, _: &Metadata) -> bool {
    file_name.starts_with('.')
}

#[cfg(windows)]
fn is_hidden(_: &str, metadata: &Metadata) -> bool {
    metadata.file_attributes() & FILE_ATTRIBUTE_HIDDEN != 0
}

#[cfg(test)]
mod test {
    //!todo
}
