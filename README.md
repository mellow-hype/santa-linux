# santa for linux proof-of-concept

This is a proof-of-concept clone of Google's [Santa](https://github.com/google/santa), a binary authorization system for macOS. The design is similar in the use of both a kernel module and userland daemon component to make policy decisions based on the SHA256 hash of the target file being executed.

At a high level, the sequence of events on each execution is as follows:

1. The kernel module intercepts calls to the function `finalize_exec()` using a kprobe pre-handler
    - The module gets the PID of the process that is executing the target binary
2. The kernel module sends a message containing the target PID to the daemon over a generic netlink socket
    - A kernel completion is initialized and waits for a response from the daemon without blocking (but still holding execution of the target binary)
3. The daemon processes incoming messages from the kernel and parses the PID from the message
4. The daemon calculates the SHA256 sum of the target binary by reading from `/proc/<pid>/exe`
    - The daemon checks whether the hash is present on the blocklist or allowlist
    - If on the allowlist, execution is allowed
    - If on the blocklist, execution is blocked
    - If neither, the file is unknown and the decisions is based on whether Lockdown mode is enabled
6. If execution should be blocked, the daemon sends a `SIGKILL` to the target PID
7. The daemon sends an ack message to the kernel to mark the completion as complete and allow the kernel to resume exec of the target binary (assuming it wasn't killed)

## repo structure

```
├── br-output
├── docker
│   ├── Dockerfile
│   ├── container.sh
│   └── init.sh
├── ext-tree
│   ├── Config.in
│   ├── configs
│   ├── external.desc
│   ├── external.mk
│   ├── overlay
│   └── package
├── local-build.sh
├── qemu-run.sh
├── README.md
└── src
    ├── rust_santa_daemon
    ├── santa_kmod
    └── testbins
```

1. `ext-tree/`: the external buildroot tree preconfigured to build the kernel module and daemon, along with a 5.4.58 kernel and a root filesystem image containing the module and daemon.
    - `ext-tree/configs`: contains the kernel and buildroot configuration files from which new builds can be run
    - `ext-tree/package`: buildroot package recipes for the kernel module and daemon components
    - `ext-tree/overlay`: buildroot filesystem overlay files
2. `src/rust_santa_daemon`: the source code for the new santa daemon written in Rust
3. `src/santa_kmod`: the source code for the santa kernel module
4. `local-build.sh`: a convenience script to run a complete build of the buildroot environment and the santa packages
4. `qemu-run.sh`: a convenience script to run a QEMU VM with the kernel and root filesystem images


## example output


```
# /allowme
[santa-DAEMON]: ALLOWLISTED (ALLOW) /allowme -> f5d5379e0ec9b97813f546bd12029657b7c51135fcd8439bca9333ab1dfdf557
i should be ALLOWED - my PID is 112

# /blockme
[santa-DAEMON]: BLOCKLISTED application; killing pid 113
[santa-DAEMON]: BLOCKLISTED (BLOCK) /blockme -> a92d9b7533984599bb263f703b5968db9a07f49aa6bb416faa535cd781debcbb
Killed

# /testbin
[santa-DAEMON]: UNKNOWN (ALLOW) /testbin -> ece6694532cee1c661623a6029a2f0563df841e0d2a7034077f7d8d86178ae8a
this is just a test - my PID is 114
```

## build and run via buildroot + qemu
**NOTE: Local builds have only been tested on Ubuntu 20.04 and Debian 11.0 stable.**

The `ext-tree/` directory contains an external buildroot tree preconfigured for the package.

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

### rebuilding the kernel module:

to rebuild the kernel module and filesystem image only, run this command from the output directory (`br-output`):

```bash
make -j12 santa_kmod-rebuild; make -j12 all
```


### running the image w/ QEMU
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

---

## design

### overview

As mentioned above, there are two primary components: the kernel module and the userland daemon.

### kernel module

The kernel module is responsible for the initial interception of the new execution and collecting required metadata that the daemon will need in order to make a final determination about whether execution will be allowed to continue or blocked.

The module uses the kprobe kernel infrastructure to accomplish this hooking. Rather than hooking the `execve__*` syscall functions directly, the kprobe is applied to the function `finalize_exec()`; this is done because by the time that function is called we can be assured the target binary has been loaded into memory and the data in `/proc/<pid>/` has been updated. This ensures the correct data is read when the daemon reads `/proc/<pid>/exe` to get calculate the hash of the binary that will be executed. Hooking earlier in the exec process results in `/proc/<pid>/exe` always pointing to the shell binary (i.e. because the execve hasn't completed so the process still contains the memory of whichever process it's fork()'ed from).

The module gathers the PID of the target binary as parsed from the `current` task struct and sends a message to the daemon in over a generic netlink socket using a custom protocol and command. The kernel module can also handle incoming netlink messages from the daemon.


### userland daemon
The daemon is reponsible for calculating the hash of the target binary and making an execution decision based on whether the hash is allowed, blocked, or unknown.

The daemon opens and binds to a Netlink socket that it uses to establish a comms channel with the kernel module and wait for incoming messages. When the daemon first starts up and opens the Netlink socket, it sends a special CHECK-IN message to the kernel module which the module then uses to know where to send it's messages. Upon receiving a message from the kernel, the daemon parses the PID from the message; the PID is then used to read from `/proc/<pid>/exe` in order to calculate the hash of the file being executed. Once the SHA256 hash has been calculated, the daemon checks whether the hash is present on either the allowlist or blocklist, and takes the appropriate action. If the hash is on neither, then it is unknown, and the execution decision is determined by the mode: block in Lockdown, allow in Monitor.

Reading from `/proc/<pid>/exe` has the benefit that it avoids running into time-of-check vs. time-of-use issues. Attempting to have the daemon use the file path alone resulted in at least 2 reads happening: once at execution time when the binary is loaded into the process space and once when the daemon would read the file to calculate the hash. Theoretically, this could introduce a race condition where a 'bad' file gets read into the process memory at execution but is replaced with a 'good' file before the daemon reads from that path for hashing, resulting in the daemon saying "yes, allowed" incorrectly. The data at `/proc/<pid>/exe` is actually the raw entrypoint into the file handle that was opened for the execution of that process, not a regular symlink to the file on the filesystem. So, even though it seems like two reads still happen, its actually 're-reading' from the same read, as the file handle is the same and points to the data in memory, not on disk -- so replacing/removing the data on disk would make no difference. We can be sure the hash we calculated is for the same executable that's been loaded in the process that will either be allowed or blocked.

### daemon hash cache implementation
TODO

### kernel-userland communication via netlink
TODO

