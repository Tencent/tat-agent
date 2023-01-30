use std::net::UdpSocket;

use smbioslib::{table_load_from_device, DefinedStruct, SystemUuidData};

#[cfg(unix)]
mod unix;
#[cfg(unix)]
pub use unix::get_hostname;

#[cfg(windows)]
mod windows;
#[cfg(windows)]
pub use windows::get_hostname;

pub struct Uname {
    pub sys_name: String,
    pub node_name: String,
    pub release: String,
    pub version: String,
    pub machine: String,
}

pub fn get_local_ip() -> Option<String> {
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| {
            socket.connect("8.8.8.8:80")?;
            socket.local_addr()
        })
        .map(|addr| addr.ip().to_string())
        .ok()
}

pub fn get_machine_id() -> Option<String> {
    let smbios_data = table_load_from_device().unwrap();
    for (_, undefstruct) in smbios_data.iter().enumerate() {
        match undefstruct.defined_struct() {
            DefinedStruct::SystemInformation(info) => {
                if let Some(uuid_data) = info.uuid() {
                    match uuid_data {
                        SystemUuidData::Uuid(_) => return Some(uuid_data.to_string()),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    None
}
