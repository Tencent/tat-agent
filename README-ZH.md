# 自动化助手 TAT

简体中文 | [English](./README.md)

自动化助手（TencentCloud Automation Tools，TAT）是云服务器的原生运维部署工具。TAT提供自动化的远程操作方式，可直接管理实例，批量执行 Shell，Powershell，Batch 等命令，轻松完成运行自动化运维脚本、轮询进程、安装或卸载软件、更新应用以及安装补丁等常见管理任务。

了解更多信息，请访问 <https://cloud.tencent.com/product/tat>

## 环境与工具

- **Rust 工具链版本 ≥ 1.82** ([安装指引](https://www.rust-lang.org/tools/install))
- **平台特定的依赖工具**:

  | 平台 | 依赖工具 |
  |----------|--------------|
  | Linux    | • Docker（[安装指引](https://docs.docker.com/engine/install/)）<br>• `cross` 工具（通过 `cargo install cross` 命令安装） |
  | Windows  | • rust MSVC 工具链 |

## 编译

执行以下命令编译：

- Linux

```shell
make linux_install_pkg
```

- Windows (使用 cmd.exe 命令行)

```batch
.\Make.bat win64-bin
```

## 安装

编译成功后，执行以下命令运行：

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

## 支持的操作系统

可以在 Linux 和 Windows 中运行，包括但不限于：

- TencentOS Server
- CentOS
- Ubuntu
- Debian
- openSUSE
- CoreOS
