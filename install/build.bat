SET RUSTFLAGS=-C target-feature=+crt-static
rustup target add i686-pc-windows-msvc
cargo build --release --target i686-pc-windows-msvc