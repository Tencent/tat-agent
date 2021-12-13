[简体中文](./README-ZH.md) | English

# TAT Agent

TAT agent is an agent written in Rust, which run in CVM, Lighthouse or CPM 2.0 instances.
Its role is to run commands remotely without ssh login, invoked from TencentCloud Console/API.
Commands include but not limited to: shell, python, php, you can provide any script interpreter
at first line, such as: #!/bin/bash, #!/usr/bin/env python3.8.
See more info at https://cloud.tencent.com/product/tat .


## prerequisites

- Rust environment, such as cargo, rustc, rustup. See more info at https://www.rust-lang.org/learn/get-started .
- Docker, some binary need to be compiled in docker.

```
# some dependencies
yum install -y gcc docker
# install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# reload your PATH environment variable to include Cargo
source $HOME/.cargo/env
# add target
rustup target add x86_64-unknown-linux-musl
rustup target add i686-unknown-linux-musl
# start docker daemon
systemctl start docker
# install tool to cross-compile Rust
cargo install cross
```


## build & install

 - Linux
```
make run
```
Build a pure static binary in release mode with the real domain, need docker installed.

 - Windows
```
.\install\build.bat
.\install\install.bat 
```

## stop

 - Linux
```
make stop
```
Stop the daemon via systemctl, or kill by pid which was written in a pidfile.

 - Windows
```
.\install\stop.bat
```

## other

See more details at Makefile.

## supported OS

Binary can run at both Linux & Windows Distributions, including but not limited to:
- Tencent Linux
- CentOS
- Ubuntu
- Debian
- openSUSE
- SUSE
- CoreOS

