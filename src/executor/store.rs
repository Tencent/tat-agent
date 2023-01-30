use log::info;
use std::fs::{create_dir_all, remove_file, File};
use std::io::prelude::*;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Local};
use rand::distributions::Alphanumeric;
use rand::{thread_rng, Rng};

use crate::common::consts;
#[cfg(test)]
use crate::common::logger;
use crate::network::types::InvocationNormalTask;

cfg_if::cfg_if! {
    if #[cfg(unix)] {
        use std::fs::{set_permissions, Permissions};
        use std::os::unix::fs::PermissionsExt;
        use std::io;
    }
}

pub struct TaskFileStore {
    store_path: PathBuf,
    prefix: String,
    log_path: PathBuf,
}

impl TaskFileStore {
    pub fn new() -> TaskFileStore {
        let t = TaskFileStore {
            store_path: Path::new(consts::TASK_STORE_PATH).to_path_buf(),
            prefix: String::from(consts::TASK_STORE_PREFIX),
            log_path: Path::new(consts::TASK_LOG_PATH).to_path_buf(),
        };
        t
    }

    pub fn get_store_path(&self) -> PathBuf {
        self.store_path.clone()
    }

    pub fn get_log_path(&self) -> PathBuf {
        self.log_path.clone()
    }

    fn get_suffix(&self, command_type: &String) -> &str {
        return match command_type.as_str() {
            consts::CMD_TYPE_SHELL => consts::SUFFIX_SHELL,
            consts::CMD_TYPE_BAT => consts::SUFFIX_BAT,
            consts::CMD_TYPE_POWERSHELL => consts::SUFFIX_PS1,
            _ => consts::SUFFIX_SHELL,
        };
    }

    fn gen_task_file_path(&self, t: &InvocationNormalTask) -> PathBuf {
        // use YYYYmm as task directory name
        // use random string as postfix
        let now: DateTime<Local> = Local::now();
        let rand_str: String = thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();

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

    pub fn get_task_log_path(&self, t: &InvocationNormalTask) -> PathBuf {
        self.get_log_path()
            .join(format!("{}.log", t.invocation_task_id))
    }

    fn create_file(
        &self,
        path: &str,
        ignore_exists: bool,
        #[cfg(unix)] executable: bool,
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
                    None => Err("").expect("should never come here"),
                },
            };
        }
        Ok(())
    }

    pub fn store(&self, t: &InvocationNormalTask) -> Result<(String, String), String> {
        let task_file_path = self.gen_task_file_path(t).display().to_string();
        info!("save task {} to {}", &t.invocation_task_id, task_file_path);

        let task_log_path = self.get_task_log_path(t).display().to_string();
        info!(
            "save task {} output to {}",
            &t.invocation_task_id, task_log_path
        );

        // store task file
        let mut file = self.create_file(
            &task_file_path,
            true,
            #[cfg(unix)]
            true,
        )?;
        let s = t.decode_command()?;
        let res = file.write_all(&s);
        if res.is_err() {
            return Err("fail to store command in task file".to_string());
        }

        Ok((task_file_path, task_log_path))
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
    use std::fs::{read, read_dir, remove_dir, remove_file};

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
            cos_bucket_url: "".to_string(),
            cos_bucket_prefix: "".to_string(),
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
                .gen_task_file_path(&task)
                .as_path()
                .parent()
                .unwrap()
                .display()
                .to_string(),
            desired_path
        );

        let (task_file, _) = store.store(&task).unwrap();
        #[cfg(unix)]
        let contents = read(&task_file).unwrap();
        #[cfg(windows)]
        let mut contents = read(&task_file).unwrap();
        #[cfg(windows)]
        {
            //check utf8 bom, start with 0xEF 0xBB 0xBF
            assert_eq!(contents[2], 0xBF);
            assert_eq!(contents[1], 0xBB);
            assert_eq!(contents[0], 0xEF);
            contents = Vec::from(&contents[3..]);
        }
        let command = String::from_utf8_lossy(contents.as_slice());
        assert_eq!(command, "ls -l");
        store.remove(&task_file);
        let paths = read_dir(Path::new(&task_file).parent().unwrap()).unwrap();
        for f in paths {
            remove_file(f.unwrap().path()).unwrap();
        }
        remove_dir(Path::new(&task_file).parent().unwrap()).unwrap();
    }
}
