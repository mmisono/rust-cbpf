# c2e
Convert a cBPF program to the eBPF program.

This program use [rbpf](https://github.com/qmonnet/rbpf)'s eBPF codes.

## Note
Currently, this program is especially for the [ubpf](https://github.com/iovisor/ubpf) VM.
ubpf VM does not support `ABS/IND/LEN` memory modes.
This program use `LDX` instruction instead of `LD_ABS` and `LD_IND`. `LD_LEN` is not supported.

In Linux, to access skb's internal data some cBPF instructions are converted
to function calls of kernel internal functions. This program just converts
cBPF instruction to corresponding eBPF one(s). So, probably the eBPF program
converted from cBPF program by this program does not work in kernel (e.g.
attaching that eBPF program by using `setsokopt()` will not work).

## Example
This crate contains a binary program called `c2e`. `c2e` creates the eBPF program from
[the libpcap's filter expressions](http://www.tcpdump.org/manpages/pcap-filter.7.html).
This program internally compile the expressions to the cBPF program using
libpcap and then convert it to the eBPF.
You can build `c2e` by `cargo build --release --bins`.

```sh
% ./target/debug/c2e  --help
c2e 0.1.0
Masanori Misono <m.misono760@gmail.com>
Convert cBPF program to eBPF from libpcap's expression

USAGE:
    c2e [FLAGS] [OPTIONS] <expression> --outfile <outfile>

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


```
% ./target/debug/c2e -d -o /dev/null "tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)"

expression: tcp port 80 and (((ip[2:2] - ((ip[0]&0xf)<<2)) - ((tcp[12]&0xf0)>>2)) != 0)
length: 80
cBPF program:
LD H ABS   {code: 28, jt: 00, jf: 00, k: 0000000C}  ldh [12]
JEQ K      {code: 15, jt: 00, jf: 06, k: 000086DD}  jeq 34525 0 6
LD B ABS   {code: 30, jt: 00, jf: 00, k: 00000014}  ldb [20]
JEQ K      {code: 15, jt: 00, jf: 04, k: 00000006}  jeq 6 0 4
LD H ABS   {code: 28, jt: 00, jf: 00, k: 00000036}  ldh [54]
JEQ K      {code: 15, jt: 0E, jf: 00, k: 00000050}  jeq 80 14 0
LD H ABS   {code: 28, jt: 00, jf: 00, k: 00000038}  ldh [56]
JEQ K      {code: 15, jt: 0C, jf: 00, k: 00000050}  jeq 80 12 0
LD H ABS   {code: 28, jt: 00, jf: 00, k: 0000000C}  ldh [12]
JEQ K      {code: 15, jt: 00, jf: 45, k: 00000800}  jeq 2048 0 69
LD B ABS   {code: 30, jt: 00, jf: 00, k: 00000017}  ldb [23]
JEQ K      {code: 15, jt: 00, jf: 43, k: 00000006}  jeq 6 0 67
LD H ABS   {code: 28, jt: 00, jf: 00, k: 00000014}  ldh [20]
JSET K     {code: 45, jt: 41, jf: 00, k: 00001FFF}  jset 8191 65 0
LDX B MSH  {code: B1, jt: 00, jf: 00, k: 0000000E}  ldxb ([14] & 0xf) << 2
LD H IND   {code: 48, jt: 00, jf: 00, k: 0000000E}  ldh [14+X]
JEQ K      {code: 15, jt: 03, jf: 00, k: 00000050}  jeq 80 3 0
LDX B MSH  {code: B1, jt: 00, jf: 00, k: 0000000E}  ldxb ([14] & 0xf) << 2
LD H IND   {code: 48, jt: 00, jf: 00, k: 00000010}  ldh [16+X]
JEQ K      {code: 15, jt: 00, jf: 3B, k: 00000050}  jeq 80 0 59
LD H ABS   {code: 28, jt: 00, jf: 00, k: 0000000C}  ldh [12]
JEQ K      {code: 15, jt: 00, jf: 39, k: 00000800}  jeq 2048 0 57
LD IMM     {code: 00, jt: 00, jf: 00, k: 00000002}  ldw 2
ST         {code: 02, jt: 00, jf: 00, k: 00000000}  st MEM[0]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 00000000}  ldxw MEM[0]
LD H IND   {code: 48, jt: 00, jf: 00, k: 0000000E}  ldh [14+X]
ST         {code: 02, jt: 00, jf: 00, k: 00000001}  st MEM[1]
LD IMM     {code: 00, jt: 00, jf: 00, k: 00000000}  ldw 0
ST         {code: 02, jt: 00, jf: 00, k: 00000002}  st MEM[2]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 00000002}  ldxw MEM[2]
LD B IND   {code: 50, jt: 00, jf: 00, k: 0000000E}  ldb [14+X]
ST         {code: 02, jt: 00, jf: 00, k: 00000003}  st MEM[3]
LD IMM     {code: 00, jt: 00, jf: 00, k: 0000000F}  ldw 15
ST         {code: 02, jt: 00, jf: 00, k: 00000004}  st MEM[4]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 00000004}  ldxw MEM[4]
LD MEM     {code: 60, jt: 00, jf: 00, k: 00000003}  ldw MEM[3]
AND X      {code: 5C, jt: 00, jf: 00, k: 00000000}  and X
ST         {code: 02, jt: 00, jf: 00, k: 00000004}  st MEM[4]
LD IMM     {code: 00, jt: 00, jf: 00, k: 00000002}  ldw 2
ST         {code: 02, jt: 00, jf: 00, k: 00000005}  st MEM[5]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 00000005}  ldxw MEM[5]
LD MEM     {code: 60, jt: 00, jf: 00, k: 00000004}  ldw MEM[4]
LSH X      {code: 6C, jt: 00, jf: 00, k: 00000000}  lsh X
ST         {code: 02, jt: 00, jf: 00, k: 00000005}  st MEM[5]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 00000005}  ldxw MEM[5]
LD MEM     {code: 60, jt: 00, jf: 00, k: 00000001}  ldw MEM[1]
SUB X      {code: 1C, jt: 00, jf: 00, k: 00000000}  sub X
ST         {code: 02, jt: 00, jf: 00, k: 00000005}  st MEM[5]
LD IMM     {code: 00, jt: 00, jf: 00, k: 0000000C}  ldw 12
ST         {code: 02, jt: 00, jf: 00, k: 00000006}  st MEM[6]
LDX B MSH  {code: B1, jt: 00, jf: 00, k: 0000000E}  ldxb ([14] & 0xf) << 2
LD MEM     {code: 60, jt: 00, jf: 00, k: 00000006}  ldw MEM[6]
ADD X      {code: 0C, jt: 00, jf: 00, k: 00000000}  add X
TAX        {code: 07, jt: 00, jf: 00, k: 00000000}  tax
LD B IND   {code: 50, jt: 00, jf: 00, k: 0000000E}  ldb [14+X]
ST         {code: 02, jt: 00, jf: 00, k: 00000007}  st MEM[7]
LD IMM     {code: 00, jt: 00, jf: 00, k: 000000F0}  ldw 240
ST         {code: 02, jt: 00, jf: 00, k: 00000008}  st MEM[8]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 00000008}  ldxw MEM[8]
LD MEM     {code: 60, jt: 00, jf: 00, k: 00000007}  ldw MEM[7]
AND X      {code: 5C, jt: 00, jf: 00, k: 00000000}  and X
ST         {code: 02, jt: 00, jf: 00, k: 00000008}  st MEM[8]
LD IMM     {code: 00, jt: 00, jf: 00, k: 00000002}  ldw 2
ST         {code: 02, jt: 00, jf: 00, k: 00000009}  st MEM[9]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 00000009}  ldxw MEM[9]
LD MEM     {code: 60, jt: 00, jf: 00, k: 00000008}  ldw MEM[8]
RSH X      {code: 7C, jt: 00, jf: 00, k: 00000000}  rsh X
ST         {code: 02, jt: 00, jf: 00, k: 00000009}  st MEM[9]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 00000009}  ldxw MEM[9]
LD MEM     {code: 60, jt: 00, jf: 00, k: 00000005}  ldw MEM[5]
SUB X      {code: 1C, jt: 00, jf: 00, k: 00000000}  sub X
ST         {code: 02, jt: 00, jf: 00, k: 00000009}  st MEM[9]
LD IMM     {code: 00, jt: 00, jf: 00, k: 00000000}  ldw 0
ST         {code: 02, jt: 00, jf: 00, k: 0000000A}  st MEM[10]
LDX MEM    {code: 61, jt: 00, jf: 00, k: 0000000A}  ldxw MEM[10]
LD MEM     {code: 60, jt: 00, jf: 00, k: 00000009}  ldw MEM[9]
SUB X      {code: 1C, jt: 00, jf: 00, k: 00000000}  sub X
JEQ K      {code: 15, jt: 01, jf: 00, k: 00000000}  jeq 0 1 0
RET K      {code: 06, jt: 00, jf: 00, k: 0000FFFF}  ret 65535
RET K      {code: 06, jt: 00, jf: 00, k: 00000000}  ret 0

eBPF program:
mov32 r0, 0x0
mov32 r6, 0x0
ldxh r0, [r1+0xc]
be16 r0
jeq r0, 0x86dd, +0x1
ja +0x9
ldxb r0, [r1+0x14]
jeq r0, 0x6, +0x1
ja +0x6
ldxh r0, [r1+0x36]
be16 r0
jeq r0, 0x50, +0x1e
ldxh r0, [r1+0x38]
be16 r0
jeq r0, 0x50, +0x1b
ldxh r0, [r1+0xc]
be16 r0
jeq r0, 0x800, +0x1
ja +0x5e
ldxb r0, [r1+0x17]
jeq r0, 0x6, +0x1
ja +0x5b
ldxh r0, [r1+0x14]
be16 r0
jset r0, 0x1fff, +0x58
ldxb r6, [r1+0xe]
and32 r6, 0xf
lsh32 r6, 0x2
mov64 r7, r1
add64 r7, r6
ldxh r0, [r7+0xe]
be16 r0
jeq r0, 0x50, +0x9
ldxb r6, [r1+0xe]
and32 r6, 0xf
lsh32 r6, 0x2
mov64 r7, r1
add64 r7, r6
ldxh r0, [r7+0x10]
be16 r0
jeq r0, 0x50, +0x1
ja +0x47
ldxh r0, [r1+0xc]
be16 r0
jeq r0, 0x800, +0x1
ja +0x43
mov32 r0, 0x2
stxw [r10+0xfffc], r0
ldxw r6, [r10+0xfffc]
mov64 r7, r1
add64 r7, r6
ldxh r0, [r7+0xe]
be16 r0
stxw [r10+0xfff8], r0
mov32 r0, 0x0
stxw [r10+0xfff4], r0
ldxw r6, [r10+0xfff4]
mov64 r7, r1
add64 r7, r6
ldxb r0, [r7+0xe]
stxw [r10+0xfff0], r0
mov32 r0, 0xf
stxw [r10+0xffec], r0
ldxw r6, [r10+0xffec]
ldxw r0, [r10+0xfff0]
add32 r0, r6
stxw [r10+0xffec], r0
mov32 r0, 0x2
stxw [r10+0xffe8], r0
ldxw r6, [r10+0xffe8]
ldxw r0, [r10+0xffec]
lsh32 r0, r6
stxw [r10+0xffe8], r0
ldxw r6, [r10+0xffe8]
ldxw r0, [r10+0xfff8]
sub32 r0, r6
stxw [r10+0xffe8], r0
mov32 r0, 0xc
stxw [r10+0xffe4], r0
ldxb r6, [r1+0xe]
and32 r6, 0xf
lsh32 r6, 0x2
ldxw r0, [r10+0xffe4]
add32 r0, r6
mov32 r6, r0
mov64 r7, r1
add64 r7, r6
ldxb r0, [r7+0xe]
stxw [r10+0xffe0], r0
mov32 r0, 0xf0
stxw [r10+0xffdc], r0
ldxw r6, [r10+0xffdc]
ldxw r0, [r10+0xffe0]
add32 r0, r6
stxw [r10+0xffdc], r0
mov32 r0, 0x2
stxw [r10+0xffd8], r0
ldxw r6, [r10+0xffd8]
ldxw r0, [r10+0xffdc]
rsh32 r0, r6
stxw [r10+0xffd8], r0
ldxw r6, [r10+0xffd8]
ldxw r0, [r10+0xffe8]
sub32 r0, r6
stxw [r10+0xffd8], r0
mov32 r0, 0x0
stxw [r10+0xffd4], r0
ldxw r6, [r10+0xffd4]
ldxw r0, [r10+0xffd8]
sub32 r0, r6
jeq r0, 0x0, +0x2
mov32 r0, 0xffff
exit
mov32 r0, 0x0
exit
```

Note that the cBPF program is compiled without optimization (since [pcap crate](https://github.com/ebfull/pcap) does not suport it for now)

## TODO
- more test
- optimization

## License
Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE).
