#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::env::{args_os, temp_dir};
    use std::{fs::remove_dir_all, io::Cursor, process::Command};

    let args = args_os().skip(1);
    let target_dir = temp_dir().join("tat_agent_install");

    let buf = include_bytes!(r"..\..\install\win-bin.zip");
    zip_extract::extract(Cursor::new(buf), &target_dir, true)?;

    // Run install command
    Command::new("sc.exe").args(&["stop", "tatsvc"]).output()?;

    let script = target_dir.join("install.bat");
    Command::new("cmd.exe")
        .arg("/C")
        .arg(script)
        .arg("only_update")
        .output()?;

    if !matches!(args.size_hint(), (_, Some(0))) {
        let system_drive = std::env::var("SystemDrive").unwrap_or("C:".to_string());
        let agent = format!("{system_drive}\\Program Files\\QCloud\\tat_agent\\tat_agent.exe");
        Command::new(agent).args(args).spawn()?;
    }

    Command::new("sc.exe").args(&["start", "tatsvc"]).output()?;
    remove_dir_all(target_dir)?;
    Ok(())
}

#[cfg(unix)]
fn main() {}
