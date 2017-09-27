extern crate core;

// cBPF opcodes
//
// see: https://github.com/the-tcpdump-group/libpcap/blob/master/pcap/bpf.h
// see also: https://www.freebsd.org/cgi/man.cgi?query=bpf

// opcode:16, jt:8, jf:8, k:32
// however, upper 8bit of opcode are not used
//
//                             7 5 4  3 2   0
//                            +--------------+
// RET: _:3, rval:2, class:3  |xxx|rval|class|
//                            +--------------+
//
//                                             7  5 4  3 2   0
//                                            +---------------+
// LD, LDX, ST, STX: mode:3, size:2, class:3  |mode|size|class|
//                                            +---------------+
//
//                                  7  4  3  2   0
//                                 +--------------+
// ALU, JMP: op:4, src:1, class:3  | op |src|class|
//                                 +--------------+
//
//                           7    3 2   0
//                          +------------+
// MISC: miscop:5, class:3  |miscop|class|
//                          +------------+
//

// class
pub const BPF_LD: u16 = 0x00;
pub const BPF_LDX: u16 = 0x01;
pub const BPF_ST: u16 = 0x02;
pub const BPF_STX: u16 = 0x03;
pub const BPF_ALU: u16 = 0x04;
pub const BPF_JMP: u16 = 0x05;
pub const BPF_RET: u16 = 0x06;
pub const BPF_MISC: u16 = 0x07;

// size
pub const BPF_W: u16 = 0x00;
pub const BPF_H: u16 = 0x08;
pub const BPF_B: u16 = 0x10;
/*              0x18    reserved */

// mode
pub const BPF_IMM: u16 = 0x00;
pub const BPF_ABS: u16 = 0x20;
pub const BPF_IND: u16 = 0x40;
pub const BPF_MEM: u16 = 0x60;
pub const BPF_LEN: u16 = 0x80;
pub const BPF_MSH: u16 = 0xa0;
/*              0xc0    reserved */
/*              0xe0    reserved */


// op
pub const BPF_ADD: u16 = 0x00;
pub const BPF_SUB: u16 = 0x10;
pub const BPF_MUL: u16 = 0x20;
pub const BPF_DIV: u16 = 0x30;
pub const BPF_OR: u16 = 0x40;
pub const BPF_AND: u16 = 0x50;
pub const BPF_LSH: u16 = 0x60;
pub const BPF_RSH: u16 = 0x70;
pub const BPF_NEG: u16 = 0x80;
pub const BPF_MOD: u16 = 0x90;
pub const BPF_XOR: u16 = 0xa0;
/*              0xb0    reserved */
/*              0xc0    reserved */
/*              0xd0    reserved */
/*              0xe0    reserved */
/*              0xf0    reserved */

pub const BPF_JA: u16 = 0x00;
pub const BPF_JEQ: u16 = 0x10;
pub const BPF_JGT: u16 = 0x20;
pub const BPF_JGE: u16 = 0x30;
pub const BPF_JSET: u16 = 0x40;
/*              0x50    reserved */
/*              0x60    reserved */
/*              0x70    reserved */
/*              0x80    reserved */
/*              0x90    reserved */
/*              0xa0    reserved */
/*              0xb0    reserved */
/*              0xc0    reserved */
/*              0xd0    reserved */
/*              0xe0    reserved */
/*              0xf0    reserved */

// src
pub const BPF_K: u16 = 0x00;
pub const BPF_X: u16 = 0x08;

// ret
pub const BPF_A: u16 = 0x10;
/*              0x18    reserved */

// misc
pub const BPF_TAX: u16 = 0x00;
pub const BPF_TXA: u16 = 0x80;
/*              0x08    reserved */
/*              0x10    reserved */
/*              0x18    reserved */
/*              0x20    reserved */
/*              0x28    reserved */
/*              0x30    reserved */
/*              0x38    reserved */
/*              0x40    reserved */
/*              0x48    reserved */
/*              0x50    reserved */
/*              0x58    reserved */
/*              0x60    reserved */
/*              0x68    reserved */
/*              0x70    reserved */
/*              0x78    reserved */
/*              0x88    reserved */
/*              0x90    reserved */
/*              0x98    reserved */
/*              0xa0    reserved */
/*              0xa8    reserved */
/*              0xb0    reserved */
/*              0xb8    reserved */
/*              0xc0    reserved */
/*              0xc8    reserved */
/*              0xd0    reserved */
/*              0xd8    reserved */
/*              0xe0    reserved */
/*              0xe8    reserved */
/*              0xf0    reserved */
/*              0xf8    reserved */


// these are possible combination
// (is there any way to generate this using macro??)
pub const BPF_RET_K: u16 = BPF_RET | BPF_K;
pub const BPF_RET_A: u16 = BPF_RET | BPF_A;

// comment out to suppress warnings regarding or-ing 0 (BPF_W is 0)
pub const BPF_LD_W_ABS: u16 = BPF_LD /*| BPF_W*/ | BPF_ABS;
pub const BPF_LD_H_ABS: u16 = BPF_LD | BPF_H | BPF_ABS;
pub const BPF_LD_B_ABS: u16 = BPF_LD | BPF_B | BPF_ABS;

pub const BPF_LD_B_LEN: u16 = BPF_LD | BPF_B | BPF_LEN;
pub const BPF_LDX_B_LEN: u16 = BPF_LDX | BPF_B | BPF_LEN;
pub const BPF_LD_W_LEN: u16 = BPF_LD /*| BPF_W*/ | BPF_LEN;
pub const BPF_LDX_W_LEN: u16 = BPF_LDX | BPF_W | BPF_LEN;

pub const BPF_LD_W_IND: u16 = BPF_LD /*| BPF_W*/ | BPF_IND;
pub const BPF_LD_H_IND: u16 = BPF_LD | BPF_H | BPF_IND;
pub const BPF_LD_B_IND: u16 = BPF_LD | BPF_B | BPF_IND;

pub const BPF_LDX_B_MSH: u16 = BPF_LDX | BPF_B | BPF_MSH;

pub const BPF_LD_IMM: u16 = BPF_LD /*| BPF_IMM*/;
pub const BPF_LDX_IMM: u16 = BPF_LDX | BPF_IMM;
pub const BPF_LD_MEM: u16 = BPF_LD | BPF_MEM;
pub const BPF_LDX_MEM: u16 = BPF_LDX | BPF_MEM;

pub const BPF_JMP_JA: u16 = BPF_JMP | BPF_JA;
pub const BPF_JGT_K: u16 = BPF_JMP | BPF_JGT | BPF_K;
pub const BPF_JGE_K: u16 = BPF_JMP | BPF_JGE | BPF_K;
pub const BPF_JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
pub const BPF_JSET_K: u16 = BPF_JMP | BPF_JSET | BPF_K;
pub const BPF_JGT_X: u16 = BPF_JMP | BPF_JGT | BPF_X;
pub const BPF_JGE_X: u16 = BPF_JMP | BPF_JGE | BPF_X;
pub const BPF_JEQ_X: u16 = BPF_JMP | BPF_JEQ | BPF_X;
pub const BPF_JSET_X: u16 = BPF_JMP | BPF_JSET | BPF_X;

pub const BPF_ADD_X: u16 = BPF_ALU | BPF_ADD | BPF_X;
pub const BPF_SUB_X: u16 = BPF_ALU | BPF_SUB | BPF_X;
pub const BPF_MUL_X: u16 = BPF_ALU | BPF_MUL | BPF_X;
pub const BPF_DIV_X: u16 = BPF_ALU | BPF_DIV | BPF_X;
pub const BPF_MOD_X: u16 = BPF_ALU | BPF_MOD | BPF_X;
pub const BPF_AND_X: u16 = BPF_ALU | BPF_AND | BPF_X;
pub const BPF_OR_X: u16 = BPF_ALU | BPF_OR | BPF_X;
pub const BPF_XOR_X: u16 = BPF_ALU | BPF_XOR | BPF_X;
pub const BPF_LSH_X: u16 = BPF_ALU | BPF_LSH | BPF_X;
pub const BPF_RSH_X: u16 = BPF_ALU | BPF_RSH | BPF_X;

pub const BPF_ADD_K: u16 = BPF_ALU | BPF_ADD | BPF_K;
pub const BPF_SUB_K: u16 = BPF_ALU | BPF_SUB | BPF_K;
pub const BPF_MUL_K: u16 = BPF_ALU | BPF_MUL | BPF_K;
pub const BPF_DIV_K: u16 = BPF_ALU | BPF_DIV | BPF_K;
pub const BPF_MOD_K: u16 = BPF_ALU | BPF_MOD | BPF_K;
pub const BPF_AND_K: u16 = BPF_ALU | BPF_AND | BPF_K;
pub const BPF_OR_K: u16 = BPF_ALU | BPF_OR | BPF_K;
pub const BPF_XOR_K: u16 = BPF_ALU | BPF_XOR | BPF_K;
pub const BPF_LSH_K: u16 = BPF_ALU | BPF_LSH | BPF_K;
pub const BPF_RSH_K: u16 = BPF_ALU | BPF_RSH | BPF_K;

pub const BPF_ALU_NEG: u16 = BPF_ALU | BPF_NEG;

pub const BPF_MISC_TAX: u16 = BPF_MISC | BPF_TAX;
pub const BPF_MISC_TXA: u16 = BPF_MISC | BPF_TXA;


pub const BPF_MEMWORDS: usize = 16;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BpfInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

#[inline]
pub fn bpf_class(code: u16) -> u16 {
    code & 0x07
}

#[inline]
pub fn bpf_size(code: u16) -> u16 {
    code & 0x18
}

#[inline]
pub fn bpf_mode(code: u16) -> u16 {
    code & 0xe0
}

#[inline]
pub fn bpf_op(code: u16) -> u16 {
    code & 0xf0
}

#[inline]
pub fn bpf_src(code: u16) -> u16 {
    code & 0x08
}

#[inline]
pub fn bpf_rval(code: u16) -> u16 {
    code & 0x18
}

#[inline]
pub fn bpf_miscop(code: u16) -> u16 {
    code & 0xf8
}

impl BpfInsn {
    pub fn new(code: u16, jt: u8, jf: u8, k: u32) -> Self {
        Self { code, jt, jf, k }
    }

    pub fn opname(code: u16) -> &'static str {
        match code {
            BPF_RET_K => "RET K",
            BPF_RET_A => "RET A",
            BPF_LD_W_ABS => "LD W ABS",
            BPF_LD_H_ABS => "LD H ABS",
            BPF_LD_B_ABS => "LD B ABS",
            BPF_LD_B_LEN => "LD B LEN",
            BPF_LDX_B_LEN => "LDX B LEN",
            BPF_LD_W_LEN => "LD W LEN",
            BPF_LDX_W_LEN => "LDX W LEN",

            BPF_ST => "ST",
            BPF_STX => "STX",

            BPF_LD_W_IND => "LD W IND",
            BPF_LD_H_IND => "LD H IND",
            BPF_LD_B_IND => "LD B IND",

            BPF_LDX_B_MSH => "LDX B MSH",

            BPF_LD_IMM => "LD IMM",
            BPF_LDX_IMM => "LDX IMM",
            BPF_LD_MEM => "LD MEM",
            BPF_LDX_MEM => "LDX MEM",

            BPF_JMP_JA => "JMP JA",
            BPF_JGT_K => "JGT K",
            BPF_JGE_K => "JGE K",
            BPF_JEQ_K => "JEQ K",
            BPF_JSET_K => "JSET K",
            BPF_JGT_X => "JGT X",
            BPF_JGE_X => "JGE X",
            BPF_JEQ_X => "JEQ X",
            BPF_JSET_X => "JSET X",

            BPF_ADD_X => "ADD X",
            BPF_SUB_X => "SUB X",
            BPF_MUL_X => "MUL X",
            BPF_DIV_X => "DIV X",
            BPF_MOD_X => "MOD X",
            BPF_AND_X => "AND X",
            BPF_OR_X => "OR X",
            BPF_XOR_X => "XOR X",
            BPF_LSH_X => "LSH X",
            BPF_RSH_X => "RSH X",

            BPF_ADD_K => "ADD K",
            BPF_SUB_K => "SUB K",
            BPF_MUL_K => "MUL K",
            BPF_DIV_K => "DIV K",
            BPF_MOD_K => "MOD K",
            BPF_AND_K => "AND K",
            BPF_OR_K => "OR K",
            BPF_XOR_K => "XOR K",
            BPF_LSH_K => "LSH K",
            BPF_RSH_K => "RSH K",

            BPF_ALU_NEG => "NEG",

            BPF_MISC_TAX => "TAX",
            BPF_MISC_TXA => "TXA",
            _ => "UNKNOWN",
        }
    }
}


impl core::fmt::Debug for BpfInsn {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> Result<(), core::fmt::Error> {
        let name = BpfInsn::opname(self.code);
        write!(
            f,
            "{:10} {{code: {:02X}, jt: {:02X}, jf: {:02X}, k: {:08X}}}  ",
            name,
            self.code,
            self.jt,
            self.jf,
            self.k,
        )?;

        match bpf_class(self.code) {
            BPF_RET => {
                write!(f, "ret ")?;
                match bpf_rval(self.code) {
                    BPF_K => write!(f, "{}", self.k)?,
                    BPF_A => write!(f, "A",)?,
                    _ => write!(f, "?")?,
                }
            }

            n @ BPF_LD | n @ BPF_LDX => {
                write!(f, "ld")?;
                if n == BPF_LDX {
                    write!(f, "x")?;
                }
                match bpf_size(self.code) {
                    BPF_W => write!(f, "w")?,
                    BPF_H => write!(f, "h")?,
                    BPF_B => write!(f, "b")?,
                    _ => write!(f, "?")?,
                }
                match bpf_mode(self.code) {
                    BPF_ABS => write!(f, " [{}]", self.k)?,
                    BPF_IND => write!(f, " [{}+X]", self.k)?,
                    BPF_IMM => write!(f, " {}", self.k)?,
                    BPF_LEN => write!(f, " len")?,
                    BPF_MSH => write!(f, " ([{}] & 0xf) << 2", self.k)?,
                    BPF_MEM => write!(f, " MEM[{}]", self.k)?,
                    _ => write!(f, " ?")?,
                }
            }

            n @ BPF_ST | n @ BPF_STX => {
                write!(
                    f,
                    "st{} MEM[{}]",
                    if n == BPF_STX { "x" } else { "" },
                    self.k
                )?;
            }

            BPF_JMP => {
                match bpf_op(self.code) {
                    BPF_JA => write!(f, "jmp")?,
                    BPF_JGT => write!(f, "jgt")?,
                    BPF_JGE => write!(f, "jge")?,
                    BPF_JEQ => write!(f, "jeq")?,
                    BPF_JSET => write!(f, "jset")?,
                    _ => write!(f, "jmp?")?,
                }
                if bpf_op(self.code) == BPF_JA {
                    write!(f, " {}", self.k)?;
                } else {
                    match bpf_src(self.code) {
                        BPF_K => write!(f, " {}", self.k)?,
                        BPF_X => write!(f, " X")?,
                        _ => write!(f, " ?")?,
                    }
                    write!(f, " {} {}", self.jt, self.jf)?;
                }
            }

            BPF_ALU => {
                match bpf_op(self.code) {
                    BPF_ADD => write!(f, "add")?,
                    BPF_SUB => write!(f, "sub")?,
                    BPF_MUL => write!(f, "mul")?,
                    BPF_DIV => write!(f, "div")?,
                    BPF_MOD => write!(f, "mod")?,
                    BPF_AND => write!(f, "and")?,
                    BPF_OR => write!(f, "or")?,
                    BPF_XOR => write!(f, "xor")?,
                    BPF_LSH => write!(f, "lsh")?,
                    BPF_RSH => write!(f, "rsh")?,
                    BPF_NEG => write!(f, "neg")?,
                    _ => write!(f, "alu?")?,
                }
                if bpf_op(self.code) != BPF_NEG {
                    match bpf_src(self.code) {
                        BPF_K => write!(f, " {}", self.k)?,
                        BPF_X => write!(f, " X")?,
                        _ => write!(f, " ?")?,
                    }
                }
            }

            BPF_MISC => match bpf_miscop(self.code) {
                BPF_TAX => write!(f, "tax")?,
                BPF_TXA => write!(f, "txa")?,
                _ => write!(f, "misc?")?,
            },

            _ => write!(f, "unknown")?,
        }

        Ok(())
    }
}
