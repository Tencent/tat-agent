# 自动化助手 TAT

简体中文 | [English](./README.md)

自动化助手（TencentCloud Automation Tools，TAT）是云服务器的原生运维部署工具。TAT提供自动化的远程操作方式，可直接管理实例，批量执行 Shell，Powershell，Python等命令，轻松完成运行自动化运维脚本、轮询进程、安装或卸载软件、更新应用以及安装补丁等常见管理任务。

了解更多信息，请访问 <https://cloud.tencent.com/product/tat>

## 环境与工具

- Rust 语言环境
- Docker

## 编译

执行以下命令编译：

- Linux 系统：

```shell
cargo build --release --bin tat_agent
```

- Windows 系统：

注意：在 Windows 系统下，rust 的版本**必须高于 1.70**，如果版本过低，可以通过以下命令更新版本：

```powershell
rustup update
```

然后运行：

```powershell
cargo build --release --bin tat_agent
```

## 运行

编译成功后，执行以下命令运行：

- Linux 系统：

```shell
./target/release/tat_agent
```

- Windows 系统：

```powershell
./target/release/tat_agent.exe
```

## 支持的操作系统

可以在 Linux 和 Windows 中运行，包括但不限于：

- TencentOS Server
- CentOS
- Ubuntu
- Debian
- SUSE
- openSUSE
- CoreOS
