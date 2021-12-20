# Changelog

All notable changes to this project will be documented in this file.

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

