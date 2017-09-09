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
    /// Currently if interpreter find illegal opcode, program will panic.
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
            if pc > insns.len() {
                return Err(PcOutOfRange);
            }
            let insn = insns[pc];
            match bpf_class(insn.code) {
                BPF_RET => {
                    return match bpf_rval(insn.code) {
                        BPF_K => Ok(insn.k),
                        BPF_A => Ok(A),
                        _ => Err(InvalidInstruction),
                    }
                }

                BPF_LD => match (bpf_size(insn.code), bpf_mode(insn.code)) {
                    (BPF_W, BPF_ABS) => {
                        let k = insn.k as usize;
                        if k > data.len() || size_of::<u32>() > data.len() - k {
                            return Err(OutOfRange);
                        }
                        A = BigEndian::read_u32(&data[k..]);
                    }
                    (BPF_H, BPF_ABS) => {
                        let k = insn.k as usize;
                        if k > data.len() || size_of::<u16>() > data.len() - k {
                            return Err(OutOfRange);
                        }
                        A = u32::from(BigEndian::read_u16(&data[k..]));
                    }
                    (BPF_B, BPF_ABS) => {
                        let k = insn.k as usize;
                        if k > data.len() {
                            return Err(OutOfRange);
                        }
                        A = u32::from(data[k]);
                    }

                    (BPF_W, BPF_LEN) => {
                        A = data.len() as u32;
                    }

                    (BPF_W, BPF_IND) => {
                        let k = (X + insn.k) as usize;
                        if k > data.len() || size_of::<u32>() > data.len() - k {
                            return Err(OutOfRange);
                        }
                        A = BigEndian::read_u32(&data[k..]);
                    }
                    (BPF_H, BPF_IND) => {
                        let k = (X + insn.k) as usize;
                        if k > data.len() || size_of::<u16>() > data.len() - k {
                            return Err(OutOfRange);
                        }
                        A = u32::from(BigEndian::read_u16(&data[k..]));
                    }
                    (BPF_B, BPF_IND) => {
                        let k = (X + insn.k) as usize;
                        if k > data.len() {
                            return Err(OutOfRange);
                        }
                        A = u32::from(data[k]);
                    }

                    (BPF_W, BPF_IMM) => {
                        A = insn.k;
                    }
                    (BPF_W, BPF_MEM) => {
                        let k = insn.k as usize;
                        if k > mem.len() {
                            return Err(OutOfRange);
                        }
                        A = mem[insn.k as usize];
                    }
                    _ => return Err(InvalidInstruction),
                },

                BPF_LDX => match (bpf_size(insn.code), bpf_mode(insn.code)) {
                    (BPF_W, BPF_LEN) => {
                        A = data.len() as u32;
                    }
                    (_, BPF_B) => if bpf_mode(insn.code) == BPF_MSH {
                        let k = insn.k as usize;
                        if k > data.len() {
                            return Err(OutOfRange);
                        }
                        X = u32::from((data[k] & 0xf) << 2);
                    } else {
                        return Err(InvalidInstruction);
                    },
                    (_, BPF_IMM) => {
                        X = insn.k;
                    }
                    (_, BPF_MEM) => {
                        let k = insn.k as usize;
                        if k > mem.len() {
                            return Err(OutOfRange);
                        }
                        X = mem[k];
                    }
                    _ => return Err(InvalidInstruction),
                },

                BPF_ST => {
                    let k = insn.k as usize;
                    if k > mem.len() {
                        return Err(OutOfRange);
                    }
                    mem[k] = A;
                }

                BPF_STX => {
                    let k = insn.k as usize;
                    if k > mem.len() {
                        return Err(OutOfRange);
                    }
                    mem[k] = X;
                }

                BPF_JMP => match (bpf_op(insn.code), bpf_src(insn.code)) {
                    (BPF_JA, _) => {
                        pc += insn.k as usize;
                    }
                    (BPF_JGT, BPF_K) => {
                        pc += {
                            if A > insn.k {
                                insn.jt as usize
                            } else {
                                insn.jf as usize
                            }
                        };
                    }
                    (BPF_JGE, BPF_K) => {
                        pc += {
                            if A >= insn.k {
                                insn.jt as usize
                            } else {
                                insn.jf as usize
                            }
                        };
                    }
                    (BPF_JEQ, BPF_K) => {
                        pc += {
                            if A == insn.k {
                                insn.jt as usize
                            } else {
                                insn.jf as usize
                            }
                        };
                    }
                    (BPF_JSET, BPF_K) => {
                        pc += {
                            if (A & insn.k) > 0 {
                                insn.jt as usize
                            } else {
                                insn.jf as usize
                            }
                        };
                    }
                    (BPF_JGT, BPF_X) => {
                        pc += {
                            if X > insn.k {
                                insn.jt as usize
                            } else {
                                insn.jf as usize
                            }
                        };
                    }
                    (BPF_JGE, BPF_X) => {
                        pc += {
                            if X >= insn.k {
                                insn.jt as usize
                            } else {
                                insn.jf as usize
                            }
                        };
                    }
                    (BPF_JEQ, BPF_X) => {
                        pc += {
                            if X == insn.k {
                                insn.jt as usize
                            } else {
                                insn.jf as usize
                            }
                        };
                    }
                    (BPF_JSET, BPF_X) => {
                        pc += {
                            if (X & insn.k) > 0 {
                                insn.jt as usize
                            } else {
                                insn.jf as usize
                            }
                        };
                    }
                    _ => return Err(InvalidInstruction),
                },

                BPF_ALU => match (bpf_op(insn.code), bpf_src(insn.code)) {
                    (BPF_ADD, BPF_X) => {
                        A += X;
                    }
                    (BPF_SUB, BPF_X) => {
                        A -= X;
                    }
                    (BPF_MUL, BPF_X) => {
                        A *= X;
                    }
                    (BPF_DIV, BPF_X) => {
                        if X == 0 {
                            return Err(DivisionByZero);
                        }
                        A /= X;
                    }
                    (BPF_MOD, BPF_X) => {
                        if X == 0 {
                            return Err(DivisionByZero);
                        }
                        A %= X;
                    }
                    (BPF_AND, BPF_X) => {
                        A &= X;
                    }
                    (BPF_OR, BPF_X) => {
                        A |= X;
                    }
                    (BPF_XOR, BPF_X) => {
                        A ^= X;
                    }
                    (BPF_LSH, BPF_X) => {
                        A <<= X;
                    }
                    (BPF_RSH, BPF_X) => {
                        A >>= X;
                    }

                    (BPF_ADD, BPF_K) => {
                        A += insn.k;
                    }
                    (BPF_SUB, BPF_K) => {
                        A -= insn.k;
                    }
                    (BPF_MUL, BPF_K) => {
                        A *= insn.k;
                    }
                    (BPF_DIV, BPF_K) => {
                        if insn.k == 0 {
                            return Err(DivisionByZero);
                        }
                        A /= insn.k;
                    }
                    (BPF_MOD, BPF_K) => {
                        if insn.k == 0 {
                            return Err(DivisionByZero);
                        }
                        A %= insn.k;
                    }
                    (BPF_AND, BPF_K) => {
                        A &= insn.k;
                    }
                    (BPF_OR, BPF_K) => {
                        A |= insn.k;
                    }
                    (BPF_XOR, BPF_K) => {
                        A ^= insn.k;
                    }
                    (BPF_LSH, BPF_K) => {
                        A <<= insn.k;
                    }
                    (BPF_RSH, BPF_K) => {
                        A >>= insn.k;
                    }

                    (BPF_NEG, _) => {
                        A = (-(A as i32)) as u32;
                    }
                    _ => return Err(InvalidInstruction),
                },

                BPF_MISC => match bpf_miscop(insn.code) {
                    BPF_TAX => X = A,
                    BPF_TXA => A = X,
                    _ => return Err(InvalidInstruction),
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

        // arp packet
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
