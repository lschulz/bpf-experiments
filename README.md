BPF Experiments
===============

- [AES-CMAC](/aes)
- [SCION-INT](/int)

Clone with `--recurse-submodules` or initialize the submodules after cloning:
```bash
git submodule update --init
```

Dependencies (Ubuntu 21.04)
---------------------------
```bash
sudo apt install build-essential linux-tools-common linux-tools-generic clang \
    libelf-dev doctest-dev libc6-dev-i386
# For the some of the tests:
sudo pip3 install scapy pyroute2
```

Build libbpf:
```bash
cd libbpf/src
make
```

Dump jited instructions on Ubuntu
---------------------------------
Ubuntu's bpftool is compiled without libbfd and cannot dump the jited BPF instructions. To compile
bpftool with libbfd available, install the the kernel source and libbfd:
```bash
sudo apt install linux-source-5.13.0 # Check kernel version with uname -r
sudo apt install llvm binutils-dev
```
Unpack the kernel source from `/usr/src/linux-source-5.13.0/linux-source-5.13.0.tar.bz2` to
somewhere convenient and run make in `tools/bpf/bpftool`.

Dump the jited program with
```bash
sudo ./bpftool prog dump jited <prog>
```
