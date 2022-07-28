BPF Experiments
===============

This repository contains a BPF XDP application intended to accelerate the reference
[SCION](https://github.com/scionproto/scion) border router by forwarding some common packet types
directly in XDP.

### Overview
- [/aes](/aes) Implementation of AES-CMAC for use in XDP as required by SCION.
- [/br](/br) The SCION XDP border router.
  - [/br/evaluation](/br/evaluation) contains some preliminary evaluation results.
- [/mac_offload](/mac_offload) Offload AES-CMAC validation from a switch to XDP.
- [/libbpfpp](/libbpfpp) C++ wrappers for libbpf
- [/libbpfpy](/libbpfpy) Python helpers for interfacing with libbpf
- [/scion](/scion) Some scripts for testing the XDP router in a dockerized local SCION topology.
- [/utils](/utils) Helper scripts for running the tests.

Requirements
------------
- Kernel >= 5.15
  - Ubuntu >= 22.04
  - Ubuntu >= 20.04.5
- llvm and clang
- pkg-config
- libelf
- patchelf
- bpftool (linux-tools-common)
- doctest (doctest-dev)
- cmake >= 3.16
- boost >= 1.78
- Python 3.10

Make sure `/usr/include/asm`, `/usr/include/bits` and `/usr/include/sys` are available. Either
install `gcc-multilib` or manually create symlinks from `/usr/include/x86_64-linux-gnu/`:
```bash
sudo ln -s /usr/include/x86_64-linux-gnu/asm /usr/include/asm
sudo ln -s /usr/include/x86_64-linux-gnu/bits /usr/include/bits
sudo mkdir /usr/include/sys
sudo ln -s /usr/include/x86_64-linux-gnu/sys/* /usr/include/sys
```

Building
--------
Clone with `--recurse-submodules` or initialize the submodules after cloning:
```bash
git submodule update --init
```

First build libbpf:
```bash
pushd libbpf/src
make
popd
```

Build the repository by invoking cmake directly
```bash
mkdir build
cd build
cmake -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ ..
make
```
or run simply run `make`.

See the various subdirectories for instructions on how to run tests etc.
