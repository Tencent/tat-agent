# TAT Agent
TAT agent is an agent written in Rust, which run in CVM or Lighthouse instances.
Its role is to run commands remotely without ssh login, invoked from TencentCloud Console/API.
Commands include but not limited to: shell, python, php, you can provide any script interpreter
at first line, such as: #!/bin/bash, #!/usr/bin/env python3.8.
See more info at https://cloud.tencent.com/product/tat .


## prerequisites

- Rust environment, such as cargo, rustc, rustup. See more info at https://www.rust-lang.org/learn/get-started .
- Docker, some binary need to be compiled in docker.

## run
```
make run
```
Run directly by cargo in debug mode with the test domain.

## build
```
make release # on linux
```
Build a pure static binary in release mode with the real domain, need docker installed.
```
.\install\build.bat # on windows
```

## stop
```
make stop
```
Stop the daemon by pid which was written in a pidfile.

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

