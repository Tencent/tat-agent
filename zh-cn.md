#TAT Agent自动化助手
TAT 代理是用 Rust 编写的代理，运行在 CVM 或 Lighthouse 实例中。
它的作用是在没有 ssh 登录的情况下远程运行命令，从腾讯云控制台/API 调用。
命令包括但不限于：shell、python、php，你可以在第一行提供任何脚本解释器
例如：#!/bin/bash、#!/usr/bin/env python3.8。在 https://cloud.tencent.com/product/tat 上查看更多信息。

环境条件
Rust 环境，如cargo、rustc、rustup。在 https://www.rust-lang.org/learn/get-started 查看更多信息。
Docker，需要在docker中编译一些二进制文件。
#运行
    make run
在调试模式下用cargo直接运行测试域名。

#构建
    make release # 在linux
使用真实域构建发布模式下的纯静态二进制文件，需要安装docker。

.\install\build.bat
# 在 Windows 上
#停止
    stop
通过写在 pidfile 中的 pid 停止守护进程。

#其他
在 Makefile 中查看更多详细信息。

#支持的操作系统
二进制可以在 Linux 和 Windows 发行版上运行，包括但不限于：

腾讯Linux
CentOS
Ubuntu
Debian
openSUSE
SUSE
核心操作系统
