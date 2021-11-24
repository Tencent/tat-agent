# Prepare

- Rust

Install Rust with command:
```
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```
See more at:
https://www.rust-lang.org/learn/get-started

- Rust target

Add target if you need, such as x86_64-unknown-linux-musl to build static target on linux:
```
rustup target add x86_64-unknown-linux-musl
```

- IDE

1. Linux command line;
2. IntelliJ IDEA with Rust plugin;
3. Visual Studio Code.

# Build

- Run directly

cargo will run immediately after build.
```
make run
```

- Build static target

cargo will only build the target.
Need x86_64-unknown-linux-musl target added and docker installed.
```
make build
```

# Run

After build, you can run tat_agent anywhere with:
```
# root user
./tat_agent
```
The tat_agent will use flock() to lock the pid file /var/run/tat_agent.pid,
to ensure only one tat_agent process can start success on one machine.
The pid file will be auto unlocked after the tat_agent exit.
So you do not need to modify the pid file manually.

# Contribute

You are welcome to report bug, or contribute from github via issue, pull request or any discussions.
