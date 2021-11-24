use crate::uname::Uname;

pub trait UnameExt {
    fn sys_name(&self) -> String;
    fn node_name(&self) -> String;
    fn release(&self) -> String;
    fn version(&self) -> String;
    fn machine(&self) -> String;
}

impl UnameExt for Uname {
    fn sys_name(&self) -> String {
        format!("{}", self.sys_name)
    }

    fn node_name(&self) -> String {
        format!("{}", self.node_name)
    }

    fn release(&self) -> String {
        format!("{}", self.release)
    }

    fn version(&self) -> String {
        format!("{}", self.version)
    }

    fn machine(&self) -> String {
        format!("{}", self.machine)
    }
}

#[cfg(test)]
mod tests {
    use crate::uname::Uname;
    use crate::uname::common::UnameExt;

    #[test]
    fn test_uname() {
        let uname = Uname::new().unwrap();
        println!("machine: {}", &uname.machine());
        #[cfg(all(unix, target_arch = "x86_64"))]
        assert_eq!(uname.machine(), "x86_64");
        #[cfg(all(unix, target_arch = "x86"))]
        assert_eq!(uname.machine(), "i686");

        println!("sys_name: {}", uname.sys_name());
        if cfg!(windows) {
            assert_eq!(uname.sys_name(), "Windows");
        } else if !cfg!(unix) {
            #[cfg(target_os = "macos")]
            assert_eq!(uname.sys_name(), "Darwin");
            #[cfg(target_os = "linux")]
            assert_eq!(uname.sys_name(), "Linux");
        };
    }
}
