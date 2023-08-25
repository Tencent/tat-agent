# TAT Agent

[简体中文](./README-ZH.md) | English

TencentCloud Automation Tools (TAT) is a native operations and maintenance deployment tool for cloud servers. TAT provides an automated way to directly manage instances and batch execute commands such as Shell, Powershell, Python, etc. to easily complete common management tasks such as running automation scripts, polling processes, installing or uninstalling software, updating applications and installing patches.

For more information, please visit <https://cloud.tencent.com/product/tat> .

## Environment & Tools

- Rust environment
- Docker

## Compile

Run the following command to compile:

- Linux

```shell
cargo build --release --bin tat_agent
```

- Windows

Note: In Windows OS, the version of rust must be **higher than 1.70**, If the version is too low, you can update the version with the following command:

```powershell
rustup update
```

Then run:

```powershell
cargo build --release --bin tat_agent
```

## Run

After successful compilation, run the following command:

- Linux

```shell
./target/release/tat_agent
```

- Windows

```powershell
./target/release/tat_agent.exe
```

## Supported OS

Binary can run at both Linux & Windows Distributions, including but not limited to:

- Tencent Linux
- CentOS
- Ubuntu
- Debian
- openSUSE
- SUSE
- CoreOS
