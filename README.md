# TAT Agent

[简体中文](./README-ZH.md) | English

TencentCloud Automation Tools (TAT) is a native operations and maintenance deployment tool for cloud servers. TAT provides an automated way to directly manage instances and batch execute commands such as Shell, Powershell, Batch, etc. to easily complete common management tasks such as running automation scripts, polling processes, installing or uninstalling software, updating applications and installing patches.

For more information, please visit <https://cloud.tencent.com/product/tat> .

## Environment & Tools

- **Rust toolchain ≥ 1.82** ([Installation Guide](https://www.rust-lang.org/tools/install))
- **Platform-specific requirements**:

  | Platform | Requirements |
  |----------|--------------|
  | Linux    | • Docker Engine ([Installation Guide](https://docs.docker.com/engine/install/))<br>• `cross` tool (`cargo install cross`) |
  | Windows  | • rust MSVC toolchain |

## Compile

Run the following command to compile:

- Linux

```shell
make linux_install_pkg
```

- Windows (use cmd.exe)

```batch
.\Make.bat win64-bin
```

## Install

After successful compilation, run the following command:

- Linux

```shell
tar -zxvf release/tat_agent_linux_install_*.tar.gz
cd tat_agent_linux_install_*/
./install.sh
```

- Windows

```batch
.\release\win_64\install.bat
```

## Supported OS

Binary can run at both Linux & Windows Distributions, including but not limited to:

- Tencent Linux
- CentOS
- Ubuntu
- Debian
- openSUSE
- CoreOS
