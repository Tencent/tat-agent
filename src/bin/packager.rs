#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env::{args_os, temp_dir};
    use std::io::Cursor;
    use std::process::Command;

    let args = args_os().skip(1);
    let target_dir = temp_dir();

    let buf = include_bytes!("..\\..\\install\\data.zip");
    zip_extract::extract(Cursor::new(buf), &target_dir, true)?;

    // Run install command
    Command::new("sc.exe").args(&["stop", "tatsvc"]).output()?;

    let winutil_path: String = temp_dir()
        .join("winutil.ps1")
        .into_os_string()
        .into_string()
        .expect("Error: Path parse failed");
    Command::new("powershell.exe")
        .args(&["-ExecutionPolicy", "Bypass", &winutil_path])
        .output()?;

    if !matches!(args.size_hint(), (_, Some(0))) {
        Command::new("C:\\Program Files\\QCloud\\tat_agent\\tat_agent.exe")
            .args(args)
            .spawn()?;
    }

    Command::new("sc.exe").args(&["start", "tatsvc"]).output()?;

    Ok(())
}

#[cfg(unix)]
fn main() {}
