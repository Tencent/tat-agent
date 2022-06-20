SET RUSTFLAGS=-C target-feature=+crt-static
rustup target add x86_64-pc-windows-msvc
cargo build --release --target x86_64-pc-windows-msvc
copy /Y target\x86_64-pc-windows-msvc\release\tat_agent.exe install\tat_agent.exe
copy /Y target\x86_64-pc-windows-msvc\release\winpty.dll install\winpty.dll
copy /Y target\x86_64-pc-windows-msvc\release\winpty-agent.exe install\winpty-agent.exe
