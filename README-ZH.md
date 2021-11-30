简体中文 | [English](./README.md)

# 自动化助手 TAT

TAT 自动化助手是由 Rust 编写，是一款可在 CVM、Lighthouse 和其他云服务器中部署的原生运维部署工具。
它的作用是在没有 ssh 登录的情况下远程运行命令，从腾讯云控制台- API 调用。
命令包括但不限于：shell、python、php，可以提供任何脚本解释器
在第一行，例如：#!/bin/bash, #!/usr/bin/env python3.8。
查看更多信息请访问https://cloud.tencent.com/product/tat

## 安装环境：

Rust：如 cargo、tustc、rustup。访问 https://www.rust-lang.org/learn/get-started 查看rust相关信息
Docker：该工具需要在Docker中进行编译

## 运行

```
make run
```
在调试模式下由 Docker 直接运行。
PS：调试模式下连接的后端为测试域名。

## 编译

在Linux系统中执行：
```
make release # on linux
```
ps：请提前安装 Docker 环境依赖
在 Windows 中执行：
```
.\install\build.bat # on windows
```

## 停止

```
make stop
```
通过写在 pidfile 中的 pid 停止守护进程。

## 其他

查看更多细节请查看 Makefile
欢迎各位补充

## 支持的操作系统

可以在Linux和Windows中运行，包括但不限于
- TencentOS Server
- CentOS
- Ubuntu
- Debian
- SUSE
- openSUSE
- CoreOS
- 其他系统欢迎补充
