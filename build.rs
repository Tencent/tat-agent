use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use std::{env, fs};

fn main() {
    if std::env::var("CARGO_CFG_WINDOWS").is_ok() {
        //build from https://github.com/rprichard/winpty.git
        let dll_path = "https://tat-1258344699.cos.ap-beijing.myqcloud.com/winpty/winpty.dll";
        let lib_path = "https://tat-1258344699.cos.ap-beijing.myqcloud.com/winpty/winpty.lib";
        let exe_path = "https://tat-1258344699.cos.ap-beijing.myqcloud.com/winpty/winpty-agent.exe";

        download(dll_path, "target/winpty/winpty.dll");
        download(lib_path, "target/winpty/winpty.lib");
        download(exe_path, "target/winpty/winpty-agent.exe");

        println!("cargo:rustc-link-search=native=target/winpty");
        println!("cargo:rustc-link-lib=dylib=winpty");

        let target_dir = get_output_path();

        let src = env::current_dir().unwrap().join("target/winpty/winpty.dll");

        let dest = target_dir.join(Path::new("winpty.dll"));
        let _ = fs::copy(src.clone(), dest);
        //for unit test
        let dest = target_dir.join(Path::new("deps/winpty.dll"));
        let _ = fs::copy(src, dest);

        let src = env::current_dir()
            .unwrap()
            .join("target/winpty/winpty-agent.exe");
        let dest = target_dir.join(Path::new("winpty-agent.exe"));
        fs::copy(src.clone(), dest).unwrap();
        //for unit test
        let dest = target_dir.join(Path::new("deps/winpty-agent.exe"));
        let _ = fs::copy(src, dest);
    }
}

fn get_output_path() -> PathBuf {
    let manifest_dir_string = env::var("CARGO_MANIFEST_DIR").unwrap();
    let build_type = env::var("PROFILE").unwrap();
    let path = Path::new(&manifest_dir_string)
        .join("target")
        .join(build_type);
    return PathBuf::from(path);
}

fn download(url: &str, file_name: &str) {
    create_dir_all(Path::new(file_name).parent().unwrap()).unwrap();
    let mut response = reqwest::blocking::get(url).unwrap();
    let mut file = std::fs::File::create(file_name).unwrap();
    response.copy_to(&mut file).unwrap();
}
