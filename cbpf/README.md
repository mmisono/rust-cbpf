# cbpf
Userspace cBPF interpreter and some related utilities.
Main functions are:

- cBPF opcode definition
- interpreter (can be used in `no-std` environment)
    - to use in `no-std`, specify `default-features=false` in the Cargo.toml
- compile cBPF program from libpcap's expression (using libpcap)

The opcodes and interpreter is based on [libpcap's bpf code](https://github.com/the-tcpdump-group/libpcap).

## Examples
This crate contains following binary programs.
You can build these binaries by `cargo build --release --bins`.

### `cbpf_build`
Compile the cBPF program from libpcap's expressions.

```sh
% ./target/debug/cbpf_compile --help
cbpf_compile 0.1.0
Masanori Misono <m.misono760@gmail.com>
Compile cBPF program using libpcap

USAGE:
    cbpf_compile [FLAGS] [OPTIONS] <expression> --outfile <outfile>

FLAGS:
    -d, --debug      Activate debug mode
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -l, --linktype <linktype>    LinkType (http://www.tcpdump.org/linktypes.html) [default: 1]
    -o, --outfile <outfile>      Output file

ARGS:
    <expression>    cBPF filter expression
```

### `cbpf_run`
Run a cbpf program with input data.

```sh
% ./target/debug/cbpf_run --help
cbpf_run 0.1.0
Masanori Misono <m.misono760@gmail.com>
Running cBPF program

USAGE:
    cbpf_run [FLAGS] [OPTIONS] <cbpf_path>

FLAGS:
    -d, --debug      Activate debug mode
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --data <data_path>    Input data

ARGS:
    <cbpf_path>    cBPF program file
```

## TODO
- more test
- add verifier
- (jit support)

## License
Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
