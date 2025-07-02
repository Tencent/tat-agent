use super::handler::{BsonHandler, Handler, HandlerExt};
use crate::network::*;

use std::fs::{create_dir, create_dir_all, read_dir, File, Metadata};
use std::iter::{once, repeat};
use std::{io::SeekFrom, path::Path, time::SystemTime};

use anyhow::Result;
use glob::Pattern;
use log::info;
use tokio::fs::{metadata, remove_dir_all, remove_file, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

cfg_if::cfg_if! {
    if #[cfg(windows)] {
        use crate::common::str2wsz;
        use std::os::windows::fs::MetadataExt;
        use winapi::um::winnt::FILE_ATTRIBUTE_HIDDEN;
        use winapi::um::fileapi::{GetDriveTypeW, GetLogicalDrives};
        use winapi::um::winbase::DRIVE_FIXED;
        const FS_TYPE_PARTITION: &str = "p";
    }
    else if #[cfg(unix)] {
        use std::os::linux::fs::MetadataExt;
        use std::os::unix::prelude::PermissionsExt;
        use std::fs::{set_permissions, Permissions};
        use uzers::{get_user_by_uid, get_group_by_gid};
        use chrono::{Local, DateTime};
    }
}

use super::{PTY_INSPECT_READ, PTY_INSPECT_WRITE};
const FS_TYPE_FILE: &str = "-";
const FS_TYPE_DIR: &str = "d";
const FS_TYPE_LINK: &str = "l";

pub async fn register_file_handlers() {
    BsonHandler::<CreateFileReq>::register().await;
    BsonHandler::<DeleteFileReq>::register().await;
    BsonHandler::<ListPathReq>::register().await;
    BsonHandler::<FileExistsReq>::register().await;
    BsonHandler::<FileInfoReq>::register().await;
    BsonHandler::<WriteFileReq>::register().await;
    BsonHandler::<ReadFileReq>::register().await;
}

impl Handler for BsonHandler<CreateFileReq> {
    const MSG_TYPE: &str = "PtyCreateFile";

    async fn process(self) {
        let id = self.id();
        let CreateFileReq {
            ref path,
            mode,
            overwrite,
            is_dir,
        } = self.request.data;
        info!(
            "=>create_file `{id}`, path: {path}, \
            is_dir: {mode}, overwrite: {overwrite}, is_dir: {is_dir}"
        );

        let path = Path::new(path);
        if path.exists() {
            // Overwriting symbolic link files is not supported.
            let is_symlink = path.is_symlink();
            // Overwriting files of different types is not supported.
            let is_different_type = (is_dir && path.is_file()) || (!is_dir && path.is_dir());

            if !overwrite || is_different_type || is_symlink {
                return self.reply(PtyBinErrMsg::new("file exists")).await;
            }
            if is_dir && path.is_dir() {
                // If the directory already exists, do nothing and return created.
                return self.reply(CreateFileResp { created: true }).await;
            }
        }

        let Some(parent_path) = path.parent() else {
            return self.reply(PtyBinErrMsg::new("invalid path")).await;
        };

        // create file as user
        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        let create_result = plugin.execute(&|| {
            create_dir_all(parent_path)?;
            if is_dir {
                create_dir(path)?;
            } else {
                File::create(path)?;
            }
            #[cfg(unix)]
            set_permissions(path, Permissions::from_mode(mode))?;
            Ok(Vec::new())
        });

        match create_result {
            Ok(_) => self.reply(CreateFileResp { created: true }).await,
            Err(e) => self.reply(PtyBinErrMsg::new(e)).await,
        }
    }
}

impl Handler for BsonHandler<DeleteFileReq> {
    const MSG_TYPE: &str = "PtyDeleteFile";

    async fn process(self) {
        let id = self.id();
        let DeleteFileReq { path, is_dir } = &self.request.data;
        info!("=>delete_file `{id}`, path: {path}, is_dir: {is_dir}");

        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        if let Err(e) = plugin.inspect_access(path, PTY_INSPECT_WRITE).await {
            return self.reply(PtyBinErrMsg::new(e)).await;
        }

        let res = if *is_dir {
            remove_dir_all(path).await
        } else {
            remove_file(path).await
        };

        match res {
            Ok(_) => self.reply(DeleteFileResp { deleted: true }).await,
            Err(e) => self.reply(PtyBinErrMsg::new(e)).await,
        };
    }
}

impl Handler for BsonHandler<ListPathReq> {
    const MSG_TYPE: &str = "PtyListPath";

    async fn process(self) {
        let id = self.id();
        let ListPathReq {
            path,
            filter,
            show_hidden,
        } = &self.request.data;
        info!("=>list_path `{id}`, path: {path}, filter: {filter}");

        let pattern = match Pattern::new(filter) {
            Ok(pattern) => pattern,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)).await,
        };

        let files = match list_path(path, &pattern, *show_hidden) {
            Ok(files) => files,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)).await,
        };

        let empty = Vec::new();
        let res = files
            .chunks(10)
            .zip(repeat(false))
            .chain(once((empty.as_slice(), true)))
            .zip(0u32..);
        for ((items, is_last), index) in res {
            self.reply(ListPathResp {
                index,
                is_last,
                files: items.to_vec(),
            })
            .await
        }
    }
}

impl Handler for BsonHandler<FileExistsReq> {
    const MSG_TYPE: &str = "PtyFileExist";

    async fn process(self) {
        let path = &self.request.data.path;
        info!("=>file_exists `{}`, path: {}", self.id(), path);
        let exists = Path::new(path).exists();
        self.reply(FileExistResp { exists }).await
    }
}

impl Handler for BsonHandler<FileInfoReq> {
    const MSG_TYPE: &str = "PtyFileInfo";

    async fn process(self) {
        let path = &self.request.data.path;
        info!("=>file_info `{}`, path: {}", self.id(), path);
        match metadata(path).await {
            Ok(metadata) => self.reply(file_info_data(path, &metadata)).await,
            Err(e) => self.reply(PtyBinErrMsg::new(e)).await,
        };
    }
}

impl Handler for BsonHandler<WriteFileReq> {
    const MSG_TYPE: &str = "PtyWriteFile";

    async fn process(self) {
        let id = self.id();
        let WriteFileReq { data, path, offset } = &self.request.data;
        info!("=>write_file `{id}`, path: {path}, offset: {offset:?}");
        //check permission
        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        if let Err(e) = plugin.inspect_access(path, PTY_INSPECT_WRITE).await {
            return self.reply(PtyBinErrMsg::new(e)).await;
        };

        let mut file = match OpenOptions::new().write(true).open(path).await {
            Ok(file) => file,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)).await,
        };

        // Write at the file's end by default if 'offset' is not provided.
        let pos = match offset {
            Some(offset) => SeekFrom::Start(*offset as u64),
            None => SeekFrom::End(0),
        };

        if let Err(e) = file.seek(pos).await {
            return self.reply(PtyBinErrMsg::new(e)).await;
        }

        match file.write(data).await {
            Ok(length) => self.reply(WriteFileResp { length }).await,
            Err(e) => self.reply(PtyBinErrMsg::new(e)).await,
        };
    }
}

impl Handler for BsonHandler<ReadFileReq> {
    const MSG_TYPE: &str = "PtyReadFile";

    async fn process(self) {
        let id = self.id();
        let ReadFileReq { path, offset, size } = &self.request.data;
        info!("=>read_file `{id}`, path: {path}, offset: {offset}, size: {size}");

        //check permission
        let plugin = &self.channel.as_ref().unwrap().plugin.component;
        if let Err(e) = plugin.inspect_access(path, PTY_INSPECT_READ).await {
            info!("read_file `{}` inspect_access failed", self.id());
            return self.reply(PtyBinErrMsg::new(e)).await;
        };

        //open file read only
        let mut file = match tokio::fs::File::open(path).await {
            Ok(file) => file,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)).await,
        };

        if let Err(e) = file.seek(SeekFrom::Start(*offset as u64)).await {
            return self.reply(PtyBinErrMsg::new(e)).await;
        };

        //use async file
        let mut remainder = *size;
        let mut offset = *offset;
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
                    })
                    .await;
                    if is_last {
                        break;
                    }
                    offset += size;
                }
                Err(e) => break self.reply(PtyBinErrMsg::new(e)).await,
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
        .filter(|l| unsafe { GetDriveTypeW(str2wsz(l).as_ptr()) } == DRIVE_FIXED)
        .collect()
}

//windows path format: /d:/work
fn list_path(path: &str, filter: &Pattern, show_hidden: bool) -> Result<Vec<FileInfoResp>> {
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

    let items = read_dir(path)?;
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
    Ok(files)
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
        longname: get_long_name(name, metadata),
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
    longname
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
