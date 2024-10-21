# TAT Agent

[简体中文](./README-ZH.md) | English

TencentCloud Automation Tools (TAT) is a native operations and maintenance deployment tool for cloud servers. TAT provides an automated way to directly manage instances and batch execute commands such as Shell, Powershell, Batch, etc. to easily complete common management tasks such as running automation scripts, polling processes, installing or uninstalling software, updating applications and installing patches.

For more information, please visit <https://cloud.tencent.com/product/tat> .

## Environment & Tools

- Rust environment

## Compile

The version of rust must be **higher than 1.80**, If the version is too low, you can update the version with the following command:

```powershell
rustup update
```

Then run the following command to compile::

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
- CoreOS
