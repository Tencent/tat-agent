# Changelog

All notable changes to this project will be documented in this file.
## [1.0.14] - 2024-03-11

### Changed

- Optimize url choose logic.

## [1.0.13] - 2024-02-24

### Changed

- Support streaming output of pty execute command on Unix system.
- Check Windows image state when Windows start.

## [1.0.12] - 2023-12-23

### Changed

- Revert script storage directory.

## [1.0.11] - 2023-12-04

### Changed

- Optimize pty login logic: add utmpx record, use system default shell.
- Change task script storage directory.
- Optimize build script.

## [1.0.10] - 2023-11-30

### Changed

- Remove temp files after task finished.

## [1.0.9] - 2023-11-23

### Changed

- Change the permissions for the config file and log files.

## [1.0.8] - 2023-11-08

### Changed

- Modify the path for uploading output to COS.
- Fix some bugs.

## [1.0.7] - 2023-10-17

### Changed

- Optimized the logic for uploading output to COS.

## [1.0.6] - 2023-09-25

### Changed

- Add config file support.

## [1.0.5] - 2023-08-25

### Changed

- Optimize CBS support.

## [1.0.4] - 2023-07-07

### Changed

- Fix performance problems.

## [1.0.3] - 2023-07-03

### Changed

- Add installer packager.
- Add consistent global snapshot support.
- Fix init script bugs.
- Update dependencies versions.

## [1.0.2] - 2023-05-26

### Changed

- Fix PtyInfoFile bugs.

## [1.0.1] - 2023-05-09

### Changed

- Add register instance.
- Add vscode proxy support.
- Optimize some logic.

## [0.1.33] - 2023-02-23

### Changed

- Optimize log record.

## [0.1.31] - 2022-11-17

### Changed

- Optimize leak check logic.

## [0.1.30] - 2022-11-15

### Changed

- Add some log for conpty mod.

## [0.1.29] - 2022-09-21

### Changed

- Add pty fs support.
- Add ps1 block support.

## [0.1.28] - 2022-08-03

### Changed

- Optimize create_user_token logic.

## [0.1.27] - 2022-07-14

### Changed

- Change reconnect time from fixed to random.

## [0.1.26] - 2022-06-29

### Changed

- Add resource leakage monitoring logic.

## [0.1.25] - 2022-06-24

### Changed

- Dispatch error msg when pty bash terminated.

## [0.1.24] - 2022-06-23

### Changed

- Fix pty stop logic.

## [0.1.23] - 2022-05-06

### Changed

- Add pty support.
- Optimize windows install scripts.

## [0.1.22] - 2022-05-06

### Changed

- Add arm support.

## [0.1.21] - 2022-04-22

### Changed

- Add new domain support.

## [0.1.20] - 2022-02-16

### Changed

- Optimize AuthenticationId logic.
- Remove utf8 bom header from powershell output on windows 2008.

## [0.1.19] - 2022-02-11

### Changed

- Change powershell default encode.
- Auto load env in /etc/profile.

## [0.1.18] - 2021-12-21

### Changed

- Support script run as user on windows platform.
- Set MAIL and TERM env for Linux.

## [0.1.17] - 2021-12-10

### Changed

- Only create log file before process being really running.
- Fix bug of sysvinit upgrade.
- Use x86_64 as default Windows target.

## [0.1.16] - 2021-12-09

### Changed

- Fix bug of write output to tmp file.

## [0.1.15] - 2021-12-05

### Changed

- Support agent smooth upgrade.
- Remove sudo dependency.
- Fix powershell script gbk error.

## [0.1.14] - 2021-12-02

### Changed

- Reduce lock holding time.
- Fix macro warnings.
- Optimize documents.

## [0.1.13] - 2021-11-18

### Changed

- Support upload task output to COS.

## [0.1.12] - 2021-11-16

### Changed

- Optimize executor logic.
- Support task cancellation.
- Remove speculate.

## [0.1.11] - 2021-10-12

### Changed

- Agent support for windows.

## [0.1.10] - 2021-10-12

### Changed

- Modify the backend domain.

## [0.1.9] - 2021-09-18

### Changed

- Report `START_FAILED` during script file creating failed because of disk full or permission deny.
- Fix some warning, replace the deprecated func.
- Modify a test case of cache lib, make it more accurate.
- Reduce some redundant log.

## [0.1.8] - 2021-08-19

### Changed

- Reduce systemd restart seconds to 1s.

## [0.1.7] - 2021-08-04

### Changed

- Optimized for preload environment.
- Use `vendored` mode for building openssl, see: [openssl](https://docs.rs/openssl/0.10.35/openssl/#vendored).
- Optimize Makefile for cross-compile.

## [0.1.6] - 2021-06-28

### Changed

- Support agent run daemon tasks.

## [0.1.5] - 2021-06-22

### Added

- Support set `username` for invocation task.
- Support preload environment variables before running task.
- Add `err_info` to store the reason for task `START_FAILED`.

## [0.1.4] - 2021-05-07

### Added

- Support containerize agent, used for E2E environment.
- Support debug mode for mock vpc info, used for E2E environment.

## [0.1.3] - 2021-04-25

### Added

- Report dropped bytes of output.
- Add CHANGELOG & LICENSE.

## [0.1.2] - 2021-01-05

### Added

- Add integration tests for HTTP API.

### Changed

- Do CheckUpdate 10s after the agent started.
- Update install.sh to adapt some bash version which do not support [[ syntax.
- Fix bug of finish time return 0 when start failed.

## [0.1.1] - 2020-12-14

### Added

- Support install for CoreOS whose /usr is Read-only.

### Changed

- Report task start & finish support retry.
- Optimize several sleep operations.
- Fix sleep method in tokio, use await instead of thread sleep.
- Fix bug, commands local saving directory recreate each month.
- Set tat_agent auto-restart time to 5s by systemd.

## [0.1.0] - 2020-11-16

### Added

- First release of TAT agent.
- Including one WebSocket thread for task notify.
- Including one HTTP thread for task query & report.
- Including one On-time thread for some periodic & timer tasks.
- Commands spawned as an independent process.
