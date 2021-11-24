use log::{error, info};
use std::fs::{create_dir_all, remove_file, File};
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use crate::common::consts;
#[cfg(test)]
use crate::common::logger;
use crate::types::InvocationNormalTask;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::fs::{set_permissions, Permissions};
        use std::os::unix::fs::PermissionsExt;
        use std::io;
        use crate::common::asserts::GracefulUnwrap;
    }
}

pub struct TaskFileStore {
    store_path: PathBuf,
    prefix: String,
}

impl TaskFileStore {
    pub fn new() -> TaskFileStore {
        let t = TaskFileStore {
            store_path: Path::new(consts::TASK_STORE_PATH).to_path_buf(),
            prefix: String::from(consts::TASK_STORE_PREFIX),
        };
        t
    }

    pub fn get_store_path(&self) -> PathBuf {
        self.store_path.clone()
    }

    fn get_suffix(&self, command_type: &String) -> &str {
        return match command_type.as_str() {
            consts::CMD_TYPE_SHELL => consts::SUFFIX_SHELL,
            consts::CMD_TYPE_BAT => consts::SUFFIX_BAT,
            consts::CMD_TYPE_POWERSHELL => consts::SUFFIX_PS1,
            _ => consts::SUFFIX_SHELL,
        };
    }

    fn get_task_file_path(&self, t: &InvocationNormalTask) -> PathBuf {
        // use YYYYmm as task directory name
        // use random string as postfix
        let now: DateTime<Local> = Local::now();
        let rand_str: String = thread_rng().sample_iter(&Alphanumeric).take(10).collect();

        let suffix = self.get_suffix(&t.command_type);
        let file_name = format!(
            "{}_{}_{}{}",
            self.prefix, t.invocation_task_id, rand_str, suffix
        );

        let file_path = self
            .get_store_path()
            .join(format!("{}", now.format("%Y%m")))
            .join(file_name);
        file_path
    }

    fn create_file(
        &self,
        path: &str,
        ignore_exists: bool,
        executable: bool,
    ) -> Result<File, String> {
        let file_path = Path::new(path);
        if file_path.exists() {
            if ignore_exists {
                match remove_file(path) {
                    Err(e) => {
                        info!("failed to remove exist file {}: {}", path, e);
                        return Err(format!("failed to remove exist file {}: {}", path, e));
                    }
                    _ => {}
                }
            } else {
                return Err(format!("file {} already exists", path));
            }
        }
        let dir = match Path::parent(file_path) {
            Some(p) => p,
            None => return Err(format!("cannot find parent directory for {:?}", file_path)),
        };
        let ret = match File::create(path) {
            Err(why) => {
                info!(
                    "couldn't create file {}, try to create directory {:?}",
                    why, dir
                );
                match create_dir_all(dir) {
                    Err(why) => Err(format!("couldn't create directory: {}", why)),
                    Ok(_) => match File::create(path) {
                        Err(why) => Err(format!("couldn't create file: {}", why)),
                        Ok(file) => Ok(file),
                    },
                }
            }
            Ok(file) => Ok(file),
        };

        #[cfg(unix)]
        if executable {
            // set permissions for path recursively, to make task-xxx.sh available for non-root user.
            match self.set_permissions_recursively(path.as_ref()) {
                Err(e) => {
                    info!("failed to chmod path recursively {}: {}", path, e);
                    return Err(format!("failed to chmod path recursively {}: {}", path, e));
                }
                _ => {}
            };
        }

        ret
    }

    #[cfg(unix)]
    fn set_permissions_recursively(&self, path: &Path) -> io::Result<()> {
        let mut path = path.clone();
        while path.to_str() != Some("/tmp") {
            match set_permissions(
                path,
                Permissions::from_mode(consts::FILE_EXECUTE_PERMISSION_MODE),
            ) {
                Err(e) => {
                    info!("failed to chmod path {:?}: {}", path, e);
                    return Err(e);
                }
                _ => match path.parent() {
                    Some(parent) => path = parent,
                    None => Err("").unwrap_or_exit("should never come here"),
                },
            };
        }
        Ok(())
    }

    pub fn store(&self, t: &InvocationNormalTask) -> Option<String> {
        let path: &str = &self.get_task_file_path(t).display().to_string();
        info!("save task {} to {}", &t.invocation_task_id, path);

        let mut file = match self.create_file(path, true, true) {
            Ok(file) => file,
            Err(e) => {
                error!("cannot create file {:?} error {:?}", path, e);
                return None;
            }
        };

        match t.decode_command() {
            Ok(s) => {
                let task_str = &s;
                match file.write_all(task_str.as_bytes()) {
                    Err(why) => {
                        error!("couldn't write {}", why);
                        None
                    }
                    Ok(_) => Some(path.to_string()),
                }
            }
            Err(e) => {
                info!(
                    "task {} command decode failed {:?}",
                    &t.invocation_task_id, e
                );
                None
            }
        }
    }

    #[cfg(test)]
    pub fn remove(&self, path: &str) {
        match remove_file(path) {
            Ok(_) => info!("remove task from {}", path),
            Err(why) => panic!("couldn't remove task: {}", why),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{read_dir, read_to_string, remove_dir, remove_file};

    #[test]
    fn test_store_task() {
        logger::init_test_log();

        #[cfg(unix)]
        let workdir = format!("/root/");
        #[cfg(windows)]
        let workdir = format!("C:\\Program Files\\qcloud\\tat_agent");
        let task = InvocationNormalTask {
            invocation_task_id: "100001".to_string(),
            command_type: format!("SHELL"),
            time_out: 30,
            command: format!("bHMgLWw="),
            username: format!("root"),
            working_directory: workdir,
        };

        let store = TaskFileStore::new();
        #[cfg(unix)]
        let desired_path = format!("/tmp/tat_agent/commands/{}", Local::now().format("%Y%m"));
        #[cfg(windows)]
        let desired_path = format!(
            "C:\\Program Files\\qcloud\\tat_agent\\tmp\\commands\\{}",
            Local::now().format("%Y%m")
        );
        assert_eq!(
            store
                .get_task_file_path(&task)
                .as_path()
                .parent()
                .unwrap()
                .display()
                .to_string(),
            desired_path
        );

        let path = store.store(&task).unwrap();
        let contents = read_to_string(&path).unwrap();
        assert_eq!(contents, "ls -l");
        store.remove(&path);
        let paths = read_dir(Path::new(&path).parent().unwrap()).unwrap();
        for f in paths {
            remove_file(f.unwrap().path()).unwrap();
        }
        remove_dir(Path::new(&path).parent().unwrap()).unwrap();
    }
}
