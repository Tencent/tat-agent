use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        // In this winpty, adjustments have been made to the part that starts a subprocess. Specifically, in the
        // handleStartProcessPacket function, the CREATE_SUSPENDED flag has been added when creating a subprocess.
        // This is done so that the new process starts in a suspended state, making it easier to switch the user
        // identity of the process later on. To inspect these changes, you can check the winpty-agent.pdb or winpty.pdb files.
        // winpty-agent.pdb  https://tat-1258344699.cos.accelerate.myqcloud.com/winpty/winpty-agent.pdb
        // winpty.pdb https://tat-1258344699.cos.accelerate.myqcloud.com/winpty/winpty.pdb

        let dll_url = "https://tat-1258344699.cos.accelerate.myqcloud.com/winpty/winpty.dll";
        let lib_url = "https://tat-1258344699.cos.accelerate.myqcloud.com/winpty/winpty.lib";
        let exe_url = "https://tat-1258344699.cos.accelerate.myqcloud.com/winpty/winpty-agent.exe";

        download(lib_url, "winpty/winpty.lib");
        println!("cargo:rustc-link-lib=dylib=winpty");
        println!("cargo:rustc-link-search=native=winpty");

        download(dll_url, "winpty/winpty.dll");
        download(exe_url, "winpty/winpty-agent.exe");

        let target_dir = get_output_path();

        let src = "winpty/winpty.dll";
        let dest = target_dir.join(Path::new("winpty.dll"));
        let _ = fs::copy(src.clone(), dest);
        //for unit test
        let dest = target_dir.join(Path::new("deps/winpty.dll"));
        let _ = fs::copy(src, dest);

        let src = "winpty/winpty-agent.exe";
        let dest = target_dir.join(Path::new("winpty-agent.exe"));
        let _ = fs::copy(src.clone(), dest);
        //for unit test
        let dest = target_dir.join(Path::new("deps/winpty-agent.exe"));
        let _ = fs::copy(src, dest);
    }
}

fn download(url: &str, file_name: &str) {
    create_dir_all(Path::new(file_name).parent().unwrap()).unwrap();
    let mut response = reqwest::blocking::get(url).unwrap();
    let mut file = std::fs::File::create(file_name).unwrap();
    response.copy_to(&mut file).unwrap();
}

fn get_output_path() -> PathBuf {
    let manifest_dir_string = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_type = env::var("PROFILE").unwrap();
    let path = Path::new(&manifest_dir_string)
        .join("target")
        .join(build_type);
    return PathBuf::from(path);
}
