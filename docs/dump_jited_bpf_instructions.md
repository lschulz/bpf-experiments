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
