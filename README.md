BPF Experiments
===============

- [AES-CMAC](/aes)
- [XDP-BR](/br)
- [SCION-INT](/int)
- [Local SCION topology for testing](/scion)

Clone with `--recurse-submodules` or initialize the submodules after cloning:
```bash
git submodule update --init
```

Dependencies (Ubuntu 21.04)
---------------------------
```bash
sudo apt install build-essential linux-tools-common linux-tools-generic clang \
    libelf-dev doctest-dev libc6-dev-i386
# For some of the tests:
sudo pip3 install scapy pyroute2
```

Build libbpf:
```bash
cd libbpf/src
make
```

Run local SCION topology with XDP-BR
------------------------------------
Clone and build SCION (by default in ~/scion):
```bash
git clone https://github.com/netsec-ethz/scion.git
pushd scion
./scion.sh bazel_remote
./scion.sh build
popd
```

Build the XDP border router and run a local SCION network:
```bash
make
cd scion
./scion run
./scion attach_xdp
```

Stop the network:
```bash
./scion stop
./scion clean
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
