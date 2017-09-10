use core::result::Result;
use core::mem::size_of;
use byteorder::{BigEndian, ByteOrder};
use opcode::*;
use Error::*;


pub trait Interpreter {
    fn run(insns: &[BpfInsn], data: &[u8]) -> Result<u32, ::Error>;
}

pub struct Simple;

impl Interpreter for Simple {
    /// Simple `cBPF` interpreter based on [libpcap implementation](https://github.com/the-tcpdump-group/libpcap/blob/master/bpf/net/bpf_filter.c)
    /// If interpreter find illegal opcode, program retrun Error.
    /// Verifier should detect such problems before execution.
    /// `data` is supposed to be big endian (network byteorder)
    fn run(insns: &[BpfInsn], data: &[u8]) -> Result<u32, ::Error> {
        #[allow(non_snake_case)]
        let mut A: u32 = 0;
        #[allow(non_snake_case)]
        let mut X: u32 = 0;
        let mut mem: [u32; BPF_MEMWORDS] = [0; BPF_MEMWORDS];

        if insns.is_empty() {
            // accept all
            return Ok(u32::max_value());
        }

        let mut pc = 0;

        loop {
            if pc >= insns.len() {
                return Err(PcOutOfRange);
            }
            let insn = insns[pc];
            match bpf_class(insn.code) {
                BPF_RET => {
                    return match bpf_rval(insn.code) {
                        BPF_A => Ok(A),
                        BPF_K => Ok(insn.k),
                        _ => Err(InvalidRval),
                    }
                }

                BPF_LD => match (bpf_size(insn.code), bpf_mode(insn.code)) {
                    (BPF_W, n @ BPF_ABS) | (BPF_W, n @ BPF_IND) => {
                        let k = (insn.k + { if n == BPF_IND { X } else { 0 } }) as usize;
                        if k >= data.len() || size_of::<u32>() > data.len() - k {
                            return Err(OutOfRange);
                        }
                        A = BigEndian::read_u32(&data[k..]);
                    }
                    (BPF_H, n @ BPF_ABS) | (BPF_H, n @ BPF_IND) => {
                        let k = (insn.k + { if n == BPF_IND { X } else { 0 } }) as usize;
                        if k >= data.len() || size_of::<u16>() > data.len() - k {
                            return Err(OutOfRange);
                        }
                        A = u32::from(BigEndian::read_u16(&data[k..]));
                    }
                    (BPF_B, n @ BPF_ABS) | (BPF_B, n @ BPF_IND) => {
                        let k = (insn.k + { if n == BPF_IND { X } else { 0 } }) as usize;
                        if k >= data.len() {
                            return Err(OutOfRange);
                        }
                        A = u32::from(data[k]);
                    }

                    (BPF_W, BPF_LEN) => {
                        A = data.len() as u32;
                    }

                    (BPF_W, BPF_IMM) => {
                        A = insn.k;
                    }
                    (BPF_W, BPF_MEM) => {
                        let k = insn.k as usize;
                        if k >= mem.len() {
                            return Err(OutOfRange);
                        }
                        A = mem[k];
                    }
                    _ => return Err(InvalidLdInstruction),
                },

                BPF_LDX => match (bpf_size(insn.code), bpf_mode(insn.code)) {
                    (BPF_W, BPF_LEN) => {
                        X = data.len() as u32;
                    }
                    (BPF_B, BPF_MSH) => {
                        let k = insn.k as usize;
                        if k >= data.len() {
                            return Err(OutOfRange);
                        }
                        X = u32::from((data[k] & 0xf) << 2);
                    }
                    (BPF_W, BPF_IMM) => {
                        X = insn.k;
                    }
                    (BPF_W, BPF_MEM) => {
                        let k = insn.k as usize;
                        if k > mem.len() {
                            return Err(OutOfRange);
                        }
                        X = mem[k];
                    }
                    _ => return Err(InvalidLdInstruction),
                },

                n @ BPF_ST | n @ BPF_STX => {
                    let k = insn.k as usize;
                    if k >= mem.len() {
                        return Err(OutOfRange);
                    }
                    mem[k] = if n == BPF_ST { A } else { X };
                }

                BPF_JMP => if bpf_op(insn.code) == BPF_JA {
                    pc += insn.k as usize;
                } else {
                    let src = match bpf_src(insn.code) {
                        BPF_K => insn.k,
                        BPF_X => X,
                        _ => return Err(InvalidSrc),
                    };

                    let cond = match bpf_op(insn.code) {
                        BPF_JGT => A > src,
                        BPF_JGE => A >= src,
                        BPF_JEQ => A == src,
                        BPF_JSET => (A & src) > 0,
                        _ => return Err(InvalidJmpCondition),
                    };

                    pc += if cond {
                        insn.jt as usize
                    } else {
                        insn.jf as usize
                    };
                },

                BPF_ALU => if bpf_op(insn.code) == BPF_NEG {
                    A = (-(A as i32)) as u32;
                } else {
                    let src = match bpf_src(insn.code) {
                        BPF_K => insn.k,
                        BPF_X => X,
                        _ => return Err(InvalidSrc),
                    };

                    match bpf_op(insn.code) {
                        BPF_ADD => A += src,
                        BPF_SUB => A -= src,
                        BPF_MUL => A *= src,
                        n @ BPF_DIV | n @ BPF_MOD => {
                            if src == 0 {
                                return Err(DivisionByZero);
                            }
                            if n == BPF_DIV {
                                A /= src;
                            } else {
                                A %= src;
                            }
                        }
                        BPF_AND => A &= src,
                        BPF_OR => A |= src,
                        BPF_XOR => A ^= src,
                        BPF_LSH => A <<= src,
                        BPF_RSH => A >>= src,
                        _ => return Err(InvalidAluOp),
                    }
                },

                BPF_MISC => match bpf_miscop(insn.code) {
                    BPF_TAX => X = A,
                    BPF_TXA => A = X,
                    _ => return Err(InvalidMiscOp),
                },

                _ => return Err(InvalidInstruction),
            }

            pc += 1;
        }
    }
}


// TODO: write more tests
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test1() {
        // a = 10; x = 20; a += x; ret a;
        let insns = [
            BpfInsn::new(BPF_LD_IMM, 0, 0, 10),
            BpfInsn::new(BPF_LDX_IMM, 0, 0, 20),
            BpfInsn::new(BPF_ADD_X, 0, 0, 0),
            BpfInsn::new(BPF_RET_A, 0, 0, 0),
        ];

        let r = Simple::run(&insns, &[]).unwrap();
        assert_eq!(r, 30);
    }

    #[test]
    fn test2() {
        // ld [12]; jne 0806, drop; ret -1; drop: ret 0;
        let insns = [
            BpfInsn::new(BPF_LD_H_ABS, 0, 0, 12),
            BpfInsn::new(BPF_JEQ_K, 0, 1, 0x0806),
            BpfInsn::new(BPF_RET_K, 0, 0, u32::max_value()),
            BpfInsn::new(BPF_RET_K, 0, 0, 0),
        ];

        // arp request packet
        let data: &[u8] = &[
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xff,
            0xf4,
            0x0f,
            0x24,
            0xff,
            0xff,
            0xff,
            0x08,
            0x06,
            0x00,
            0x01,
            0x08,
            0x00,
            0x06,
            0x04,
            0x00,
            0x01,
            0xf4,
            0x0f,
            0x24,
            0x2d,
            0x94,
            0x69,
            0xc0,
            0xa8,
            0x00,
            0x2a,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0xc0,
            0xa8,
            0x00,
            0x32,
        ];

        let r = Simple::run(&insns, &data).unwrap();
        assert_eq!(r, u32::max_value());
    }
}
