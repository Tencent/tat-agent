use super::handler::{BsonHandler, Handler, HandlerExt};
use crate::network::*;

use std::fs::{create_dir, create_dir_all, Metadata};
use std::sync::Arc;
use std::{io::SeekFrom, path::Path, time::SystemTime};

use anyhow::Result;
use futures::{stream, StreamExt};
use glob::Pattern;
use log::info;
use tokio::fs::{metadata, read_dir, remove_dir_all, remove_file, File, OpenOptions};
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};
use tokio_stream::wrappers::ReadDirStream;

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
            mode: {mode:o}, overwrite: {overwrite}, is_dir: {is_dir}"
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
                std::fs::File::create(path)?;
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

        #[cfg(windows)]
        if path == "/" {
            let drives = get_win32_ready_drives()
                .into_iter()
                .map(|name| FileInfoResp {
                    r#type: FS_TYPE_PARTITION.to_string(),
                    name,
                    size: 0,
                    modify_time: 0,
                    access_time: 0,
                })
                .collect();
            let reply = ListPathResp {
                index: 0,
                is_last: true,
                files: drives,
            };
            return self.reply(reply).await;
        }
        #[cfg(windows)]
        let path = {
            let i = if path.starts_with("/") { 1 } else { 0 };
            &path[i..]
        };

        let pattern = match Pattern::new(filter) {
            Ok(pattern) => Arc::new(pattern),
            Err(e) => return self.reply(PtyBinErrMsg::new(e)).await,
        };

        let read_dir = match read_dir(path).await {
            Ok(read_dir) => read_dir,
            Err(e) => return self.reply(PtyBinErrMsg::new(e)).await,
        };
        ReadDirStream::new(read_dir)
            .filter_map(|entry| {
                let pattern = pattern.clone();
                let show_hidden = *show_hidden;
                async move {
                    let entry = entry.ok()?;
                    let metadata = entry.metadata().await.ok()?;
                    let name_os_string = entry.file_name();
                    let name = name_os_string.to_string_lossy();
                    (show_hidden || !is_hidden(&name, &metadata)).then_some(())?;
                    pattern.matches(&name).then_some(())?;
                    Some(file_info_data(&name, &metadata))
                }
            })
            .chunks(10)
            .zip(stream::repeat(false))
            .chain(stream::once(async { (Vec::new(), true) }))
            .enumerate()
            .for_each(|(index, (files, is_last))| {
                self.reply(ListPathResp {
                    index,
                    is_last,
                    files,
                })
            })
            .await;
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

        match file.write_all(data).await {
            Ok(_) => self.reply(WriteFileResp { length: data.len() }).await,
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
        let mut file = match File::open(path).await {
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

fn file_info_data(name: &str, metadata: &Metadata) -> FileInfoResp {
    fn timestamp(t: SystemTime) -> Result<u64> {
        Ok(t.duration_since(SystemTime::UNIX_EPOCH)?.as_millis() as u64)
    }

    let fs_type = if metadata.is_dir() {
        FS_TYPE_DIR.to_string()
    } else if metadata.is_symlink() {
        FS_TYPE_LINK.to_string()
    } else {
        FS_TYPE_FILE.to_string()
    };

    let modify_time = metadata.modified().unwrap();
    let access_time = metadata.accessed().unwrap();

    #[cfg(unix)]
    let mode = unix_mode::to_string(metadata.permissions().mode());
    #[cfg(unix)]
    let longname = get_long_name(name, metadata, &mode, modify_time);

    FileInfoResp {
        r#type: fs_type,
        name: name.to_owned(),
        size: metadata.len(),
        modify_time: timestamp(modify_time).unwrap(),
        access_time: timestamp(access_time).unwrap(),

        #[cfg(unix)]
        owner: metadata.st_uid(),
        #[cfg(unix)]
        group: metadata.st_gid(),
        #[cfg(unix)]
        rights: mode,
        #[cfg(unix)]
        longname,
    }
}

#[cfg(unix)]
fn get_long_name(name: &str, metadata: &Metadata, mode: &str, modify_time: SystemTime) -> String {
    let owner = get_user_by_uid(metadata.st_uid());
    let owner_name = owner
        .as_ref()
        .map(|user| user.name().to_string_lossy())
        .unwrap_or("unknown".into());

    let group = get_group_by_gid(metadata.st_gid());
    let group_name = group
        .as_ref()
        .map(|group| group.name().to_string_lossy())
        .unwrap_or("unknown".into());

    let link_count = metadata.st_nlink();
    let size = metadata.st_size();
    let time = {
        let datetime: DateTime<Local> = modify_time.into();
        format!("{}", datetime.format("%b %d %R"))
    };

    format!(
        "{} {} {} {} {} {} {}",
        mode, link_count, owner_name, group_name, size, time, name
    )
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
