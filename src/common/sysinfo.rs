use std::{cmp::min, num::NonZeroUsize, thread::available_parallelism};
use std::{env::consts::OS, net::UdpSocket, sync::LazyLock};

use anyhow::{anyhow, Result};
use smbioslib::{table_load_from_device, DefinedStruct, SystemUuidData};
use sysinfo::{set_open_files_limit, System};
use tokio::sync::{Mutex, MutexGuard};

const MAX_PARALLELISM: usize = 8;
static MACHINE_ID: LazyLock<Result<String>> = LazyLock::new(get_machine_id);

pub async fn system() -> MutexGuard<'static, System> {
    static SYSTEM: LazyLock<Mutex<System>> = LazyLock::new(|| {
        set_open_files_limit(10);
        Mutex::new(System::new())
    });
    SYSTEM.lock().await
}

pub fn local_ip() -> Result<String> {
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("8.8.8.8:80")?;
    let addr = socket.local_addr()?;
    Ok(addr.ip().to_string())
}

fn get_machine_id() -> Result<String> {
    if let Some(machine_id) = smbios_machine_id() {
        return Ok(machine_id);
    }
    machine_uid::get().map_err(|e| anyhow!("{}", e))
}

fn smbios_machine_id() -> Option<String> {
    let smbios_data = table_load_from_device().ok()?;
    for undefstruct in smbios_data.iter() {
        let DefinedStruct::SystemInformation(info) = undefstruct.defined_struct() else {
            continue;
        };
        if let Some(uuid_data @ SystemUuidData::Uuid(_)) = info.uuid() {
            return Some(uuid_data.to_string());
        }
    }
    None
}

pub fn machine_id() -> Result<&'static str> {
    MACHINE_ID.as_deref().map_err(|e| anyhow!(e))
}

pub fn kernel_name() -> String {
    let mut os = OS.to_string();
    os.get_mut(0..1).unwrap().make_ascii_uppercase();
    os
}

pub fn kernel_version() -> String {
    System::kernel_version().unwrap_or(String::from("<unknown>"))
}

pub fn os_version() -> String {
    System::long_os_version().unwrap_or(String::from("<unknown>"))
}

pub fn cpu_arch() -> String {
    System::cpu_arch()
}

pub fn hostname() -> Option<String> {
    System::host_name()
}

pub fn uptime_secs() -> u64 {
    System::uptime()
}

pub fn parallelism() -> usize {
    let sys_parallelism = available_parallelism().map_or(1, NonZeroUsize::get);
    min(sys_parallelism, MAX_PARALLELISM)
}
