use super::RESTART_CHECK_INVL;
use crate::network::{HttpRequester, Invoke, InvokeAdapter};
use crate::{common::create_file_with_parents, EXE_DIR};

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use futures::StreamExt;
use log::{debug, info};
use tokio::{fs::remove_dir_all, io::AsyncWriteExt, process::Command, time::sleep};
use zip::ZipArchive;

const SELF_UPDATE_DIR: &str = "self_update";
const SELF_UPDATE_FILENAME: &str = "agent_update.zip";
const UPDATE_FILE_UNZIP_DIR: &str = "agent_update_unzip";
const AGENT_FILENAME: &str = "tat_agent";
const UPDATE_DOWNLOAD_TIMEOUT: u64 = 20 * 60;
#[cfg(unix)]
const SELF_UPDATE_SCRIPT: &str = "self_update.sh";
#[cfg(windows)]
const SELF_UPDATE_SCRIPT: &str = "self_update.bat";

fn self_update_dir() -> PathBuf {
    EXE_DIR.join(SELF_UPDATE_DIR)
}

fn self_update_unzip_dir() -> PathBuf {
    self_update_dir().join(UPDATE_FILE_UNZIP_DIR)
}

pub async fn check_update(stop_counter: &Arc<AtomicU64>) {
    match update().await {
        Err(e) => return InvokeAdapter::log(&format!("try_update error: {e:#}")).await,
        Ok(false) => return, // no newer version
        _ => (),
    }
    wait_and_restart(stop_counter).await
}

async fn wait_and_restart(stop_counter: &Arc<AtomicU64>) -> ! {
    while stop_counter.load(Ordering::SeqCst) != 0 {
        sleep(RESTART_CHECK_INVL).await;
    }

    info!("restart needed, no tasks running, restart program");
    if let Err(e) = restart().await {
        InvokeAdapter::log(&format!("restart agent failed: {e:#}")).await;
    }
    // should not comes here, because agent should has been killed when called `restart()`.
    std::process::exit(2);
}

async fn update() -> Result<bool> {
    let rsp = InvokeAdapter::check_update()
        .await
        .context("check_update requset failed")?;
    if !rsp.need_update {
        info!("no newer version to update now");
        return Ok(false);
    }
    let (url, md5) = rsp
        .download_url
        .zip(rsp.md5)
        .context("invalid check_update response: no download_url or md5")?;

    info!("newer agent version found, going to download");

    let dir = self_update_dir();
    let zip = dir.join(SELF_UPDATE_FILENAME);
    let actual_md5 = download_file(&url, &zip).await.context("download failed")?;
    if !md5.eq_ignore_ascii_case(&actual_md5) {
        bail!("download_file md5 `{actual_md5}` mismatch with expected `{md5}`");
    }

    let unzip_dir = self_update_unzip_dir();
    unzip_file(zip, unzip_dir).context("unzip_file failed")?;
    info!("self update file unzip success");

    #[cfg(unix)]
    {
        batch_chmod().await.context("batch_chmod failed")?;
        info!("self update script batch_set_execute_permission success");
    }

    let op = verify_agent().await.context("try_run_agent failed")?;
    info!("try run new agent --version success: {}", op.escape_debug());

    run_self_update_script().await.context("script failed")?;
    info!("agent self update script run success, will restart later gracefully");
    Ok(true)
}

async fn download_file(from: &str, to: impl AsRef<Path>) -> Result<String> {
    let path = to.as_ref();
    let mut file = create_file_with_parents(path)
        .await
        .context(format!("file `{path:?}` create failed"))?;

    info!("start to download file from: {from}");
    let mut bytes_stream = HttpRequester::get(&from)
        .timeout(UPDATE_DOWNLOAD_TIMEOUT)
        .send()
        .await
        .context("request failed")?
        .bytes_stream();

    let mut md5 = md5::Context::new();
    while let Some(item) = bytes_stream.next().await {
        let bytes = item.context("bytes_stream get item failed")?;
        file.write_all(&*bytes).await.context("write_all failed")?;
        md5.consume(bytes);
    }
    file.sync_all().await.context("sync_all failed")?;

    let md5 = format!("{:x}", md5.compute());
    info!("download_file success, save to: {path:?}, md5: {md5}");
    Ok(md5)
}

fn unzip_file(from: impl AsRef<Path>, to: impl AsRef<Path>) -> Result<()> {
    let zip = std::fs::File::open(from)?;
    ZipArchive::new(zip)?.extract(to)?;
    Ok(())
}

#[cfg(unix)]
async fn batch_chmod() -> Result<()> {
    use crate::common::set_permissions_recursively;
    use crate::executor::unix::EXEC_MODE;
    use std::{fs::Permissions, os::unix::fs::PermissionsExt};
    use tokio::fs::set_permissions;

    let perm = Permissions::from_mode(EXEC_MODE);
    let unzip_dir = self_update_unzip_dir();
    let agent = unzip_dir.join(AGENT_FILENAME);
    set_permissions(agent, perm.clone()).await?;

    let update_script = unzip_dir.join(SELF_UPDATE_SCRIPT);
    set_permissions_recursively(update_script, Some(&*EXE_DIR), perm).await
}

async fn verify_agent() -> Result<String> {
    let agent = self_update_unzip_dir().join(AGENT_FILENAME);
    let out = Command::new(agent).arg("--version").output().await?;

    let version = String::from_utf8(out.stdout).context("agent version contains invalid char")?;
    let v = version.split(' ').collect::<Vec<_>>();
    if v.len() != 2 || v[0] != AGENT_FILENAME {
        bail!("version output invalid: {}", version.escape_debug());
    }
    Ok(version)
}

async fn run_self_update_script() -> Result<()> {
    let script = self_update_unzip_dir().join(SELF_UPDATE_SCRIPT);
    #[cfg(unix)]
    let out = Command::new("sh").arg("-c").arg(script).output().await?;
    #[cfg(windows)]
    let out = Command::new(script).output().await?;

    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    debug!("stdout of self update script:[{}]", stdout);
    debug!("stderr of self update script:[{}]", stderr);

    out.status.success().then_some(()).context(format!(
        "exit code: {:?}, stderr: {stderr}",
        out.status.code(),
    ))
}

pub async fn restart() -> Result<()> {
    #[cfg(unix)]
    let out = {
        let script = include_str!(r"../../install/install.sh");
        Command::new("sh")
            .args(&["-c", script, "install.sh", "restart"])
            .output()
            .await?
    };
    #[cfg(windows)]
    // TODO: Update to call 'install.bat restart' in future version
    let out = Command::new("cmd.exe")
        .args(["/C", "sc stop tatsvc & sc start tatsvc"])
        .output()
        .await?;

    let stdout = String::from_utf8_lossy(out.stdout.as_slice());
    let stderr = String::from_utf8_lossy(out.stderr.as_slice());
    debug!("stdout of restart agent:[{}]", stdout);
    debug!("stderr of restart agent:[{}]", stderr);

    out.status.success().then_some(()).context(format!(
        "exit code: {:?}, stderr: {stderr}",
        out.status.code(),
    ))
}

pub async fn remove_update_file() {
    let _ = remove_dir_all(self_update_dir()).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::logger::init_test_log;

    #[tokio::test]
    async fn test_self_update() {
        init_test_log();
        let res = update().await;
        assert!(res.is_ok());
        assert!(res.unwrap());
    }
}
