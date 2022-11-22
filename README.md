# santa for linux proof-of-concept

This is a proof-of-concept clone of Google's [Santa](https://github.com/google/santa), a binary authorization system for macOS. The design is similar in the use of both a kernel module and userland daemon component to make policy decisions based on the SHA256 hash of the target file being executed.

```sh
# show the current rules
$ santactl rule show
{
  "a92d9b7533984599bb263f703b5968db9a07f49aa6bb416faa535cd781debcbb": "Block",
  "f5d5379e0ec9b97813f546bd12029657b7c51135fcd8439bca9333ab1dfdf557": "Allow"
}

# the allowlisted binary
$ ./allowme
i should be ALLOWED - my PID is 135

# the blocklisted binary
$ ./blockme
Killed

# logs
$ cat /var/log/santad.log
Successfully daemonized the santad process...
[...]
[santa-DAEMON]: UNKNOWN (ALLOW) /usr/bin/santactl -> 2585c6fef89e4b231c2a8ef16779b6475a2f0678f7bb7deaa3ddd30e56a5d20b
[santa-DAEMON]: ALLOWLISTED (ALLOW) /allowme -> f5d5379e0ec9b97813f546bd12029657b7c51135fcd8439bca9333ab1dfdf557
[santa-DAEMON]: BLOCKLISTED (BLOCK) /blockme -> a92d9b7533984599bb263f703b5968db9a07f49aa6bb416faa535cd781debcbb
[santa-DAEMON]: UNKNOWN (ALLOW) /usr/bin/coreutils -> 60271e6b1fee7fdfa8a4f25410bcfb6d6cb5e4c8ff236cb0b928ea577130a5da
```

## Features

1. Multiple enforcement modes: Monitor mode for enforcing a blocklist policy only and Lockdown mode for enforcing an allowlist policy (i.e. only allowlisted binaries are allowed).
2. SHA256-based rules: create allowlist/blocklist rules based on the SHA256 hash of target binaries. The ruleset can be provided via JSON file using a simple k:v format: `"<hash>: <rule>` or inserted at runtime using the `santactl rule insert` command.
3. Hash Cache: the daemon implements a caching layer to avoid having to re-hash recently hashed files to improve performance. The cache is implemented as a fixed-size FIFO queue, and the oldest entries are only removed once the cache capacity is reached.

## Known Issues/Limitations
Extensive testing has not been done yet and this is very much still a proof-of-concept implementation. It's not meant to be functional on a full machine or even useful for anything practical at this point.

## TODO & Unimplemented Features

* Scope-based rules (i.e. path-based rules)
* Cleaner exception handling in the daemon
* Allow the daemon to re-checkin in case of failures
* Improve IPC validation/authentication between components

--- 

# Architecture & Design

## Execution Flow
The sequence of events that take place on each execution and the process that Santa takes to make a decision on whether execution will be allowed or denied is described below.

### Kernel
1. The kernel module hooks calls to the kernel function `finalize_exec()` using a kprobe pre-handler. After a call to an execve variant, this function is called to complete the exec setup process, right before execution is actually handed to the binary’s entry point
    - The module gets the PID of the process that is executing the target binary by reading from `task_struct *current`
2. The kernel module sends a message containing the target PID to the daemon over a generic netlink socket.

### User-Space
1. The daemon loops indefinitely, processes incoming messages from the kernel. Upon receiving a message it parses the PID from the message payload.
2. The daemon attaches the the process pointed to by the PID via ptrace and holds execution
2. The daemon gets the SHA256 hash of the target binary
    - It first calculates a unique signature using file metadata and checks the cache to see if the signature is found. If it is, this hash is used.
    - If the signature was not found in the cache, the daemon calculates the hash by reading from `/proc/<pid>/exe` and performing the shasum operation
3. The daemon checks whether the hash is present on the blocklist or allowlist
    - If on the allowlist: execution is allowed
    - If on the blocklist: execution is blocked
    - If neither: the file is unknown and the decisions is based on whether Lockdown mode is enabled
4. If execution should be blocked, the daemon sends a `SIGKILL` signal to the target PID. Otherwise the daemon detaches from the process and execution is allowed to proceed.

## Components
### Kernel Module

The kernel module is responsible for the initial interception of the new execution and collecting required metadata that the daemon will need in order to make a final determination about whether execution will be allowed to continue or blocked.

The module gathers the PID of the target binary as parsed from the `current` task struct and sends a message to the daemon in over a generic netlink socket using a custom protocol and command. The kernel module can also handle incoming netlink messages from the daemon.

The module uses the kprobe kernel infrastructure to accomplish this hooking. Rather than hooking the `execve__*` syscall functions directly, the kprobe is applied to the function `finalize_exec()`; this is done because by the time that function is called we can be assured the target binary has been loaded into memory and the data in `/proc/<pid>/` has been updated. This ensures the correct data is read when the daemon reads `/proc/<pid>/exe` to get calculate the hash of the binary that will be executed. Hooking earlier in the exec process results in `/proc/<pid>/exe` always pointing to the shell binary from which the exec spawned.

### Santa Daemon

The daemon is reponsible for calculating the hash of the target binary and making execution decisions based on whether the target binary’s hash is allowlisted, blocklisted, or unknown. The daemon opens and binds to the kernel’s Netlink socket that it uses to establish a comms channel with the kernel module and wait for incoming messages. 

Upon receiving a message from the kernel, the daemon parses the PID from the message payload and uses it to read from `/proc/<pid>/exe` in order to calculate the hash of the file being executed. Once the SHA256 hash has been calculated, the daemon checks whether the hash is present on either the allowlist or blocklist, and takes the appropriate action. If the hash is on neither, then it is unknown, and the execution decision is determined by the mode: block in Lockdown, allow in Monitor.

### Santactl

The `santactl` binary is used to interact with the daemon at runtime. It can be used to insert or remove rules, show known rules, and get daemon information such as the current mode and size of the ruleset. It also offers a feature for having the daemon’s policy engine analyze a target file and report whether it is known and would be allowed or blocked.

## IPC

Two different IPC mechanisms are used to handle bi-directional communication between the different components: Generic Netlink and Unix domain sockets.

### Kernel-Daemon Communication: Generic Netlink

The kernel module and daemon components communicate over a Netlink socket using a custom generic netlink protocol. The kernel module registers a new Netlink family and associated handlers for the different commands the protocol understands. There are 4 supported commands:

```
MSG - Generic message command
CHECK-IN - Command the daemon sends to check-in w/ kernel
DO-HASH - Command the kernel mod sends to daemon to init hash job
HASH-DONE - Command the daemon sends the kernel to signal hash job completion
```

Messages are automatically validated by the kernel through the generic netlink interface and on the daemon side through Rust’s strong typing and exhaustive pattern checking.

### Santactl-Daemon Communication: Unix Domain sockets

Communication between the `santactl` and the daemon happens over standard Unix domain sockets. At runtime, the daemon creates and binds to a socket at `/opt/santa/santad.xpc` where it expects to receive messages from `santactl`. Similarly, `santactl` will create and bind to a socket at `/opt/santa/santactl.xpc` where it expects to receive responses back from the daemon. Each of these components connects to the other’s receiver socket to send messages. Messages are defined using structs that derive the `serde::Serialize` and `serde::Deserialize` traits, and are JSON serialized before being sent on the socket and deserialized back to their respective structs on the receiving end.

---

# Concepts
## Mode

The Santa daemon operates in one of two modes:

- **Monitor:** executions are hooked and explicit blocklist rules are honored, but unknown binaries are allowed to run.
- **Lockdown**: the same as monitor mode, except the default policy is to block any binary that is not explicitly allowlisted.

The mode is currently hardcoded into the daemon binary and changing the mode requires recompiling the binary. 

**TODO: Add option to switch modes using `santactl`.**

WARNING: Lockdown mode will almost certainly bork the system and make it completely unusable without having hashed and allowlisted at least everything in `/bin:/usr/bin:/sbin:/usr/sbin` first. I haven’t tested this mode at all  yet.

## Rules

This current implementation only supports rules defined by the SHA256 hash of a target binary. The daemon reads the ruleset at runtime from a JSON file at `/opt/santa/rules.json`. This file has a simple format:

```json
{
	"<hash>": "<ALLOW|BLOCK>"
}
```

Its also possible to add or remove rules using the `santactl rule <insert|remove>` subcommands.

Although the macOS version of Santa supports creating rules based on the signing certificate for signed applications, this doesn’t translate well to the Linux ecosystem since application signing is not really a thing there, so that likely won’t be added to this version. 

**TODO: add support for scope-based rules (i.e. path-based allowlisting)** 

## Cache

The daemon implements a caching mechanism to keep the hashes of the most recently hashed files and avoid having to re-hash files on each execution, since that operations can be computationally expensive depending on the size of the target binary.

The cache is implemented as a fixed-size FIFO queue using a combination of a `HashMap` and vector that tracks inserted keys in an ordered fashion. Upon reaching the cache capacity, the oldest keys in the vector queue are dropped and removed from the HashMap. Cache lookups get the benefit of HashMap lookup speeds.

---

# Binaries

## santa-daemon

```
santa-daemon

Usage: santa-daemon [OPTIONS]

Options:
  -d, --daemonize  Whether the process should daemonize or not
  -h, --help       Print help information
```

**NOTE**: When the daemon is started with the `-d` flag to daemonize, it will log STDOUT to `/var/log/santad.log` and STDERR to `/var/log/santad_err.log`.

## santactl

```
santactl is used to interact with the santa-daemon

Usage: santactl <COMMAND>

Commands:
  status    Get status info from the daemon
  fileinfo  Analyze and get info on a target file
  rule      Manage the daemon's ruleset
  help      Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help information
```

### Daemon Status
This command can be used to query stats from the santa daemon.

```bash
$ santactl status
{
  "mode": "Monitor",
  "rule_count": 2,
  "cache_count": 4
}
```

### Rule Management
This command can be used to view and manage the ruleset at runtime.

```
Manage the daemon's ruleset

Usage: santactl rule <COMMAND>

Commands:
  show    Show rules
  insert  Insert rules
  delete  Delete rules
  help    Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help information
```

### File Info

```
Analyze and get info on a target file

Usage: santactl fileinfo <PATH>

Arguments:
  <PATH>

Options:
  -h, --help  Print help information
```

```bash
$ santactl fileinfo --path /testbin
{
  "filepath": "/testbin",
  "hash": "ece6694532cee1c661623a6029a2f0563df841e0d2a7034077f7d8d86178ae8a",
  "decision": "Allow",
  "reason": "Unknown"
}
```
---

# Build and Run the Buildroot+QEMU Environment

The `ext-tree/` directory contains an external buildroot tree pre-configured to build a 5.4.58 Linux kernel, the Santa kernel module and binaries, and a minimal root filesystem with everything included and configured to start at boot. The kernel image and root filesystem can be run via QEMU.

```
├── br-output
├── ext-tree
│   ├── Config.in
│   ├── configs
│   ├── external.desc
│   ├── external.mk
│   ├── overlay/
│   └── package/
```

1. `ext-tree/`: the external buildroot tree preconfigured to build the kernel module and daemon, along with a 5.4.58 kernel and a root filesystem image containing the module and daemon.
    - `ext-tree/configs`: contains the kernel and buildroot configuration files from which new builds can be run
    - `ext-tree/package`: buildroot package recipes for the kernel module and daemon components
    - `ext-tree/overlay`: buildroot filesystem overlay files
2. `src/rust_santa_daemon`: the source code for the new santa daemon written in Rust
3. `src/santa_kmod`: the source code for the santa kernel module
4. `local-build.sh`: a convenience script to run a complete build of the buildroot environment and the santa packages
4. `qemu-run.sh`: a convenience script to run a QEMU VM with the kernel and root filesystem images

## build
**NOTE: Local builds have only been tested on Ubuntu 20.04 and Debian 11.0 stable.**

### install dependencies
```bash
sudo apt update && apt install -y \
    build-essential \
    bzip2 \
    gzip \
    lzop \
    liblzma-dev \
    liblzo2-dev \
    ocaml-nox \
    gawk \
    p7zip-full \
    python3 \
    python3-lzo \
    python3-pip \
    squashfs-tools \
    tar \
    unzip \
    perl \
    rsync \
    fakeroot \
    ccache ecj fastjar \
    gettext git java-propose-classpath libelf-dev libncurses5-dev \
    libncursesw5-dev libssl-dev python python2.7-dev \
    python3-setuptools python3-dev subversion \
    pkg-config \
    wget \
    cpio \
    bc \
    zlib1g-dev
```

### full build
From the root directory of the repo, run the following command to download buildroot and initialize a new build to output to the `br-output` directory:

```bash
mkdir -p br-output
wget -c https://buildroot.org/downloads/buildroot-2022.08.tar.gz -O - | tar -xz
cd buildroot-2022.08/
make O="$PWD/../br-output" BR2_EXTERNAL="$PWD/../ext-tree" rust-santa-clone-qemu_x86_64_defconfig
cd ../br-output
```

The buildroot kernel image, minimal root filesystem image, santa kernel module, and santa daemon can be built using these commands:

```bash
# the targets say 'rebuild' but this still works on the first run
make -j12 santa_kmod-rebuild
make -j12 rust_santa_daemon-rebuild
make -j12 all
```

### rebuilding the daemon

to rebuild the daemon component and filesystem image only, run this command from the output directory (`br-output`):

```bash
make -j12 rust_santa_daemon-rebuild; make -j12 all
```

### rebuilding the kernel module

to rebuild the kernel module and filesystem image only, run this command from the output directory (`br-output`):

```bash
make -j12 santa_kmod-rebuild; make -j12 all
```


## running the image w/ QEMU
the resulting kernel image and root filesystem will have the kernel module and daemon binaries included, as well as config files to ensure both are automatically loaded and started at boot.

the image can be run with QEMU using the following command:

```bash
export IMAGE_DIR="br-output/images"
qemu-system-x86_64                                                                      \
        -m 512M                                                                         \
        -M pc                                                                           \
        -cpu qemu64                                                                     \
        -kernel ${IMAGE_DIR}/bzImage                                                    \
        -drive file="${IMAGE_DIR}"/rootfs.ext2,if=virtio,format=raw                     \
        -append "rw nokaslr panic=1 root=/dev/vda console=tty1 console=ttyS0"           \
        -no-reboot                                                                      \
        -nographic                                                                      \
        -serial mon:stdio                                                               \
        -s                                                                              \
        -net nic,model=virtio -net user
```

## santa auto-start in the vm
The filesystem that is created as part of the buildroot VM contains files that will configure the Santa kernel module to be loaded and the santa-daemon process to start automatically at boot:

- `ext-tree/overlay/etc/init.d/S90modules`
- `ext-tree/overlay/etc/init.d/S99santa_daemon`

