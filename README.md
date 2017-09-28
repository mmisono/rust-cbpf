# cbpf-rust
[![Linux Build Status](https://travis-ci.org/mmisono/rust-cbpf.svg?branch=master)](https://travis-ci.org/mmisono/rust-cbpf)

This repository have two crates:

- [`cbpf`](./cbpf) : Userspace cBPF interpreter which can be run in a `no-std`
  environment and some related utilities.
- [`c2e`](./c2e) : Convert a cBPF program to the eBPF program.

Please see each directory for more details.

## Note
The main purpose of this project is to create eBPF programs which can be run
in my personal environment that use [ubpf](https://github.com/iovisor/ubpf) as
eBPF VM from libpcap's expressions.

This project is under development. Maybe there are some problems.

## Related Project
- [libpcap](https://github.com/the-tcpdump-group/libpcap) : Contains userspace
  cBPF interpreter and compiler
- [pcap](https://github.com/ebfull/pcap): pcap library for rust
- [ubpf](https://github.com/iovisor/ubpf) : Userspace eBPF VM written in C
- [rbpf](https://github.com/qmonnet/rbpf) : Userspace eBPF VM written in rust
- [bpfjit](https://github.com/polachok/bpfjit): cBPF jit compiler for rust
  (internally it use libpcap's code)
