// cbpf to ebpf
// https://www.kernel.org/doc/Documentation/networking/filter.txt
//
// op:16, jt:8, jf:8, k:32 => op:8, dst_reg:4, src_reg:4, off:16, imm:32
//
// for alu / jmp
//  +----------------+--------+--------------------+
//  |   4 bits       |  1 bit |   3 bits           |
//  | operation code | source | instruction class  |
//  +----------------+--------+--------------------+
//  (MSB)                                      (LSB)
//
//  class
//    cbpf                   ebpf
//  BPF_LD    0x00          BPF_LD    0x00
//  BPF_LDX   0x01          BPF_LDX   0x01
//  BPF_ST    0x02          BPF_ST    0x02
//  BPF_STX   0x03          BPF_STX   0x03
//  BPF_ALU   0x04          BPF_ALU   0x04
//  BPF_JMP   0x05          BPF_JMP   0x05
//  BPF_RET   0x06          [ class 6 unused, for future if needed ]
//  BPF_MISC  0x07          BPF_ALU64 0x07
//
//  source
//  BPF_K     0x00
//  BPF_X     0x08     ebpf: use src reg
//
//  opcode
//
//  alu/alu64
//
//    BPF_ADD   0x00
//    BPF_SUB   0x10
//    BPF_MUL   0x20
//    BPF_DIV   0x30
//    BPF_OR    0x40
//    BPF_AND   0x50
//    BPF_LSH   0x60
//    BPF_RSH   0x70
//    BPF_NEG   0x80
//    BPF_MOD   0x90
//    BPF_XOR   0xa0
//    BPF_MOV   0xb0  /* eBPF only: mov reg to reg */   TAX, TXA
//    BPF_ARSH  0xc0  /* eBPF only: sign extending shift right */
//    BPF_END   0xd0  /* eBPF only: endianness conversion */
//
//  jmp
//
//    BPF_JA    0x00
//    BPF_JEQ   0x10
//    BPF_JGT   0x20
//    BPF_JGE   0x30
//    BPF_JSET  0x40
//    BPF_JNE   0x50  /* eBPF only: jump != */
//    BPF_JSGT  0x60  /* eBPF only: signed '>' */
//    BPF_JSGE  0x70  /* eBPF only: signed '>=' */
//    BPF_CALL  0x80  /* eBPF only: function call */
//    BPF_EXIT  0x90  /* eBPF only: function return */ // no ret, store return value into register R0
//
//
//  load
//   +--------+--------+-------------------+
//   | 3 bits | 2 bits |   3 bits          |
//   |  mode  |  size  | instruction class |
//   +--------+--------+-------------------+
//   (MSB)                             (LSB)
//
// size
//   BPF_W   0x00    /* word */
//   BPF_H   0x08    /* half word */
//   BPF_B   0x10    /* byte */
//   BPF_DW  0x18    /* eBPF only, double word */
//
// mode
//   BPF_IMM  0x00  /* used for 32-bit mov in classic BPF and 64-bit in eBPF */
//   BPF_ABS  0x20
//   BPF_IND  0x40
//   BPF_MEM  0x60
//   BPF_LEN  0x80  /* classic BPF only, reserved in eBPF */
//   BPF_MSH  0xa0  /* classic BPF only, reserved in eBPF */
//   BPF_XADD 0xc0  /* eBPF only, exclusive add */
//

use cbpf::opcode::*;
use cbpf::Error;
use cbpf::Error::*;
use rbpf::ebpf;
use rbpf::ebpf::Insn;

#[allow(dead_code)]
mod reg {
    pub const R0: u8 = 0; // return value
    pub const R1: u8 = 1; // 1st argument
    pub const R2: u8 = 2; // 2nd argument
    pub const R3: u8 = 3; // 3rd argument
    pub const R4: u8 = 4; // 4th argument
    pub const R5: u8 = 5; // 5th argument
    pub const R6: u8 = 6;
    pub const R7: u8 = 7;
    pub const R8: u8 = 8;
    pub const R9: u8 = 9;
    pub const R10: u8 = 10; // frame pointer (read only)

    // we use R0 for REG_A and R6 for REG_X. This can be changed
    pub const REG_A: u8 = R0;
    pub const REG_X: u8 = R6;
    pub const REG_TMP: u8 = R7;
}
use self::reg::*;

fn to_bytes(insns: &[Insn]) -> Vec<u8> {
    let mut prog = vec![];
    for insn in insns.iter() {
        prog.extend(insn.to_vec());
    }
    prog
}

/// convert cBPF program to eBPF program
/// first convert each cbpf instruction to ebpf instruction(s),
/// then adjust jump offset
/// XXX: this convertion is for [ubpf](https://github.com/iovisor/ubpf)
///      rbpf and linux kernel's ebpf interpreter are slightly different from that of ubpf
pub fn convert(insns: &[BpfInsn]) -> Result<Vec<u8>, Error> {
    let mut prog = vec![];

    // init REG_A, REG_X
    prog.push(vec![
        Insn {
            opc: ebpf::MOV32_IMM,
            src: 0,
            dst: REG_A,
            off: 0,
            imm: 0,
        },
        Insn {
            opc: ebpf::MOV32_IMM,
            src: 0,
            dst: REG_X,
            off: 0,
            imm: 0,
        },
    ]);

    // convert each instruction
    for insn in insns {
        match bpf_class(insn.code) {
            BPF_RET => {
                // ebpf has no ret instruction; use mov R0 <rval> + exit
                match bpf_rval(insn.code) {
                    BPF_A => {
                        prog.push(vec![
                                /*
                                 * currently we use R0 as REG_A, so we don't need to move REG_A to R0
                                Insn {
                                    opc: ebpf::MOV32_REG
                                    src: REG_A,
                                    dst: R0,
                                    off: 0,
                                    imm: 0,
                                },
                                */
                                Insn {
                                    opc: ebpf::EXIT,
                                    src: 0,
                                    dst: 0,
                                    off: 0,
                                    imm: 0,
                                },
                            ]);
                    }
                    BPF_K => {
                        prog.push(vec![
                            Insn {
                                opc: ebpf::MOV32_IMM,
                                src: 0,
                                dst: R0,
                                off: 0,
                                imm: insn.k as i32,
                            },
                            Insn {
                                opc: ebpf::EXIT,
                                src: 0,
                                dst: 0,
                                off: 0,
                                imm: 0,
                            },
                        ]);
                    }

                    _ => return Err(InvalidRval),
                }
            }

            // XXX: ubpf does not support ABS/IND/LEN mode (rbpf does ABS/IND mode)
            // for LD_ABS, use LDX instruction to load data via R1 (R1 is the first argument)
            // for LD_IND, use REG_TMP (R7) register as offset register and use LDX instruction
            // for LD_MEM, use stack (R10) as memory
            // Note that the type of offset of LDX is i16, while that of imm of cBPF is u32
            // TODO: offset overflow check
            BPF_LD => {
                match (bpf_size(insn.code), bpf_mode(insn.code)) {
                    (BPF_W, BPF_ABS) => prog.push(vec![
                        Insn {
                            opc: ebpf::LD_W_REG,
                            src: R1,
                            dst: REG_A,
                            off: insn.k as i16,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::BE, /* XXX: Use htobe to convert be to host byte order */
                            src: 0,
                            dst: REG_A,
                            off: 0,
                            imm: 32,
                        },
                    ]),
                    (BPF_H, BPF_ABS) => prog.push(vec![
                        Insn {
                            opc: ebpf::LD_H_REG,
                            src: R1,
                            dst: REG_A,
                            off: insn.k as i16,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::BE,
                            src: 0,
                            dst: REG_A,
                            off: 0,
                            imm: 16,
                        },
                    ]),
                    (BPF_B, BPF_ABS) => prog.push(vec![
                        Insn {
                            opc: ebpf::LD_B_REG,
                            src: R1,
                            dst: REG_A,
                            off: insn.k as i16,
                            imm: 0,
                        },
                    ]),
                    (BPF_W, BPF_IND) => prog.push(vec![
                        // REG_TMP <= R1 + REG_X
                        // REG_A <= [REG_TMP]
                        Insn {
                            opc: ebpf::MOV64_REG,
                            src: R1,
                            dst: REG_TMP,
                            off: 0,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::ADD64_REG,
                            src: REG_X,
                            dst: REG_TMP,
                            off: 0,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::LD_W_REG,
                            src: REG_TMP,
                            dst: REG_A,
                            off: insn.k as i16,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::BE,
                            src: 0,
                            dst: REG_A,
                            off: 0,
                            imm: 32,
                        },
                    ]),
                    (BPF_H, BPF_IND) => prog.push(vec![
                        Insn {
                            opc: ebpf::MOV64_REG,
                            src: R1,
                            dst: REG_TMP,
                            off: 0,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::ADD64_REG,
                            src: REG_X,
                            dst: REG_TMP,
                            off: 0,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::LD_H_REG,
                            src: REG_TMP,
                            dst: REG_A,
                            off: insn.k as i16,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::BE,
                            src: 0,
                            dst: REG_A,
                            off: 0,
                            imm: 16,
                        },
                    ]),
                    (BPF_B, BPF_IND) => prog.push(vec![
                        Insn {
                            opc: ebpf::MOV64_REG,
                            src: R1,
                            dst: REG_TMP,
                            off: 0,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::ADD64_REG,
                            src: REG_X,
                            dst: REG_TMP,
                            off: 0,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::LD_B_REG,
                            src: REG_TMP,
                            dst: REG_A,
                            off: insn.k as i16,
                            imm: 0,
                        },
                    ]),
                    (BPF_W, BPF_LEN) => return Err(InvalidInstruction),
                    (BPF_W, BPF_IMM) => prog.push(vec![
                        Insn {
                            opc: ebpf::MOV32_IMM,
                            src: 0,
                            dst: REG_A,
                            off: 0,
                            imm: insn.k as i32,
                        },
                    ]),
                    (BPF_W, BPF_MEM) => prog.push(vec![
                        Insn {
                            opc: ebpf::LD_W_REG,
                            src: R10,
                            dst: REG_A,
                            off: -(1 + insn.k as i16) * 4,
                            imm: 0,
                        },
                    ]),
                    (_, _) => return Err(InvalidLdInstruction),
                };
            }

            BPF_LDX => {
                match (bpf_size(insn.code), bpf_mode(insn.code)) {
                    (BPF_W, BPF_LEN) => return Err(InvalidLdInstruction),
                    // no MSH instruction in ebpf
                    (BPF_B, BPF_MSH) => prog.push(vec![
                        Insn {
                            opc: ebpf::LD_B_REG,
                            src: R1,
                            dst: REG_X,
                            off: insn.k as i16,
                            imm: 0,
                        },
                        Insn {
                            opc: ebpf::AND32_IMM,
                            src: 0,
                            dst: REG_X,
                            off: 0,
                            imm: 0xf,
                        },
                        Insn {
                            opc: ebpf::LSH32_IMM,
                            src: 0,
                            dst: REG_X,
                            off: 0,
                            imm: 2,
                        },
                    ]),
                    (BPF_W, BPF_IMM) => prog.push(vec![
                        Insn {
                            opc: ebpf::MOV32_IMM,
                            src: 0,
                            dst: REG_X,
                            off: 0,
                            imm: insn.k as i32,
                        },
                    ]),
                    (BPF_W, BPF_MEM) => prog.push(vec![
                        Insn {
                            opc: ebpf::LD_W_REG,
                            src: R10,
                            dst: REG_X,
                            off: -(1 + insn.k as i16) * 4,
                            imm: 0,
                        },
                    ]),
                    (_, _) => return Err(InvalidLdInstruction),
                };
            }

            BPF_ST => {
                prog.push(vec![
                    Insn {
                        opc: ebpf::ST_W_REG,
                        src: REG_A,
                        dst: R10,
                        off: -(1 + insn.k as i16) * 4,
                        imm: 0,
                    },
                ]);
            }

            BPF_STX => {
                prog.push(vec![
                    Insn {
                        opc: ebpf::ST_W_REG,
                        src: REG_X,
                        dst: R10,
                        off: -(1 + insn.k as i16) * 4,
                        imm: 0,
                    },
                ]);
            }

            BPF_JMP => if bpf_op(insn.code) == BPF_JA {
                prog.push(vec![
                    Insn {
                        opc: ebpf::JA,
                        src: 0,
                        dst: 0,
                        off: insn.k as i16,
                        imm: 0,
                    },
                ]);
            } else {
                // ebpf has no jf field
                // simply insert a JA instruction after jump
                match bpf_src(insn.code) {
                    BPF_K => {
                        let opc = match bpf_op(insn.code) {
                            BPF_JGT => ebpf::JGT_IMM,
                            BPF_JGE => ebpf::JGE_IMM,
                            BPF_JEQ => ebpf::JEQ_IMM,
                            BPF_JSET => ebpf::JSET_IMM,
                            _ => return Err(InvalidJmpCondition),
                        };
                        // TODO: optimization if insn.jt == 0
                        let mut is = vec![
                            Insn {
                                opc: opc,
                                src: 0,
                                dst: REG_A,
                                off: insn.jt as i16,
                                imm: insn.k as i32,
                            },
                        ];
                        if insn.jf != 0 {
                            is.push(Insn {
                                opc: ebpf::JA,
                                src: 0,
                                dst: 0,
                                off: insn.jf as i16,
                                imm: 0,
                            });
                        }
                        prog.push(is);
                    }

                    BPF_X => {
                        let opc = match bpf_op(insn.code) {
                            BPF_JGT => ebpf::JGT_REG,
                            BPF_JGE => ebpf::JGE_REG,
                            BPF_JEQ => ebpf::JEQ_REG,
                            BPF_JSET => ebpf::JSET_REG,
                            _ => return Err(InvalidJmpCondition),
                        };
                        prog.push(vec![
                            Insn {
                                opc: opc,
                                src: 0,
                                dst: REG_X,
                                off: insn.jt as i16,
                                imm: 0,
                            },
                            Insn {
                                opc: ebpf::JA,
                                src: 0,
                                dst: 0,
                                off: insn.jf as i16,
                                imm: 0,
                            },
                        ]);
                    }
                    _ => return Err(InvalidSrc),
                }
            },

            BPF_ALU => if bpf_op(insn.code) == BPF_NEG {
                prog.push(vec![
                    Insn {
                        opc: ebpf::NEG32,
                        src: 0,
                        dst: REG_A, // dst = -dst
                        off: 0,
                        imm: 0,
                    },
                ]);
            } else {
                match bpf_src(insn.code) {
                    BPF_K => {
                        let opc = match bpf_op(insn.code) {
                            BPF_ADD => ebpf::ADD32_IMM,
                            BPF_SUB => ebpf::SUB32_IMM,
                            BPF_MUL => ebpf::MUL32_IMM,
                            BPF_DIV => ebpf::DIV32_IMM,
                            BPF_MOD => ebpf::MOD32_IMM,
                            BPF_AND => ebpf::ADD32_IMM,
                            BPF_OR => ebpf::OR32_IMM,
                            BPF_XOR => ebpf::XOR32_IMM,
                            BPF_LSH => ebpf::LSH32_IMM,
                            BPF_RSH => ebpf::RSH32_IMM,
                            _ => return Err(InvalidAluOp),
                        };
                        prog.push(vec![
                            Insn {
                                opc: opc,
                                src: 0,
                                dst: REG_A,
                                off: 0,
                                imm: insn.k as i32,
                            },
                        ]);
                    }
                    BPF_X => {
                        let opc = match bpf_op(insn.code) {
                            BPF_ADD => ebpf::ADD32_REG,
                            BPF_SUB => ebpf::SUB32_REG,
                            BPF_MUL => ebpf::MUL32_REG,
                            BPF_DIV => ebpf::DIV32_REG,
                            BPF_MOD => ebpf::MOD32_REG,
                            BPF_AND => ebpf::ADD32_REG,
                            BPF_OR => ebpf::OR32_REG,
                            BPF_XOR => ebpf::XOR32_REG,
                            BPF_LSH => ebpf::LSH32_REG,
                            BPF_RSH => ebpf::RSH32_REG,
                            _ => return Err(InvalidAluOp),
                        };
                        prog.push(vec![
                            Insn {
                                opc: opc,
                                src: REG_X,
                                dst: REG_A,
                                off: 0,
                                imm: 0,
                            },
                        ]);
                    }
                    _ => return Err(InvalidSrc),
                };
            },
            BPF_MISC => match bpf_miscop(insn.code) {
                BPF_TAX => {
                    prog.push(vec![
                        Insn {
                            opc: ebpf::MOV32_REG,
                            src: REG_A,
                            dst: REG_X,
                            off: 0,
                            imm: 0,
                        },
                    ]);
                }
                BPF_TXA => {
                    prog.push(vec![
                        Insn {
                            opc: ebpf::MOV32_REG,
                            src: REG_X,
                            dst: REG_A,
                            off: 0,
                            imm: 0,
                        },
                    ]);
                }
                _ => return Err(InvalidMiscOp),
            },
            _ => return Err(InvalidInstruction),
        }
    }

    // emit final program
    let mut p = vec![];
    let mut insn_count = vec![0];
    for (i, insns) in prog.iter().enumerate() {
        let l = insns.len() + insn_count[i];
        insn_count.push(l);
    }
    for (i, insns) in prog.into_iter().enumerate() {
        for (j, mut insn) in insns.into_iter().enumerate() {
            if (ebpf::BPF_CLS_MASK & insn.opc) == ebpf::BPF_JMP {
                // adjust jump offset
                if insn_count.len() > (i + insn.off as usize + 1) {
                    insn.off = ((insn_count[i + insn.off as usize + 1]) as i16)
                        - (insn_count[i] as i16) - (j as i16) - 1;
                } else {
                    // something go wrong
                    return Err(InvalidInstruction);
                }
            }
            p.push(insn);
        }
    }
    Ok(to_bytes(&p))
}


// TODO: write more tests
// run `RUST_TEST_THREADS=1 cargo test -- --nocapture` to check output
#[cfg(test)]
mod test {
    use super::*;
    use rbpf;
    use cbpf::interpreter::{Interpreter, Simple};

    #[test]
    fn test1() {
        // a = 10; x = 20; a += x; ret a;
        let insns = [
            BpfInsn::new(BPF_LD_IMM, 0, 0, 10),
            BpfInsn::new(BPF_LDX_IMM, 0, 0, 20),
            BpfInsn::new(BPF_ADD_X, 0, 0, 0),
            BpfInsn::new(BPF_RET_A, 0, 0, 0),
        ];

        let ebpf_insns = [
            ebpf::Insn {
                opc: ebpf::MOV32_IMM,
                src: 0,
                dst: REG_A,
                off: 0,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::MOV32_IMM,
                src: 0,
                dst: REG_X,
                off: 0,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::MOV32_IMM,
                src: 0,
                dst: REG_A,
                off: 0,
                imm: 10,
            },
            ebpf::Insn {
                opc: ebpf::MOV32_IMM,
                src: 0,
                dst: REG_X,
                off: 0,
                imm: 20,
            },
            ebpf::Insn {
                opc: ebpf::ADD32_REG,
                src: REG_X,
                dst: REG_A,
                off: 0,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::EXIT,
                src: 0,
                dst: 0,
                off: 0,
                imm: 0,
            },
        ];

        let ebpf_prog = convert(&insns).unwrap();
        println!();
        rbpf::disassembler::disassemble(&ebpf_prog);
        assert_eq!(&ebpf_prog, &to_bytes(&ebpf_insns));


        let cr = Simple::run(&insns, &[]).unwrap();
        let vm = rbpf::EbpfVmRaw::new(&ebpf_prog);
        let er = vm.prog_exec(&mut []);
        assert_eq!(cr, er as u32);
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

        let ebpf_insns = [
            ebpf::Insn {
                opc: ebpf::MOV32_IMM,
                src: 0,
                dst: REG_A,
                off: 0,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::MOV32_IMM,
                src: 0,
                dst: REG_X,
                off: 0,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::LD_H_REG,
                src: R1,
                dst: REG_A,
                off: 12,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::BE,
                src: 0,
                dst: REG_A,
                off: 0,
                imm: 16,
            },
            ebpf::Insn {
                opc: ebpf::JEQ_IMM,
                src: 0,
                dst: 0,
                off: 1,
                imm: 0x0806,
            },
            ebpf::Insn {
                opc: ebpf::JA,
                src: 0,
                dst: 0,
                off: 2,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::MOV32_IMM,
                src: 0,
                dst: REG_A,
                off: 0,
                imm: u32::max_value() as i32,
            },
            ebpf::Insn {
                opc: ebpf::EXIT,
                src: 0,
                dst: 0,
                off: 0,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::MOV32_IMM,
                src: 0,
                dst: REG_A,
                off: 0,
                imm: 0,
            },
            ebpf::Insn {
                opc: ebpf::EXIT,
                src: 0,
                dst: 0,
                off: 0,
                imm: 0,
            },
        ];


        // arp request packet
        let mut data: &mut [u8] = &mut [
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

        let ebpf_prog = convert(&insns).unwrap();
        println!();
        rbpf::disassembler::disassemble(&ebpf_prog);
        assert_eq!(&ebpf_prog, &to_bytes(&ebpf_insns));

        let cr = { Simple::run(&insns, &data).unwrap() };
        let vm = rbpf::EbpfVmRaw::new(&ebpf_prog);
        let er = vm.prog_exec(&mut data);
        assert_eq!(cr, er as u32);
    }

    #[test]
    fn test3() {
        let insns = [
            BpfInsn::new(BPF_LDX_B_MSH, 0, 0, 3),
            BpfInsn::new(BPF_MISC_TXA, 0, 0, 0),
            BpfInsn::new(BPF_RET_A, 0, 0, 0),
        ];
        let ebpf_prog = convert(&insns).unwrap();
        println!();
        rbpf::disassembler::disassemble(&ebpf_prog);

        let mut data: &mut [u8] = &mut [0x11, 0x12, 0x13, 0x14];
        let cr = { Simple::run(&insns, &data).unwrap() };
        let vm = rbpf::EbpfVmRaw::new(&ebpf_prog);
        let er = vm.prog_exec(&mut data);
        assert_eq!(cr, er as u32);
    }

    #[test]
    fn test4() {
        let insns = [
            BpfInsn::new(BPF_JA, 0, 0, 1),
            BpfInsn::new(BPF_MISC_TXA, 0, 0, 0),
            BpfInsn::new(BPF_LD_IMM, 0, 0, 10),
            BpfInsn::new(BPF_JEQ_K, 0, 3, 20),
            BpfInsn::new(BPF_MISC_TXA, 0, 0, 0),
            BpfInsn::new(BPF_MISC_TXA, 0, 0, 0),
            BpfInsn::new(BPF_RET_K, 0, 0, 1),
            BpfInsn::new(BPF_JGE_K, 0, 1, 10),
            BpfInsn::new(BPF_RET_K, 0, 0, 2),
            BpfInsn::new(BPF_RET_K, 0, 0, 3),
        ];
        let ebpf_prog = convert(&insns).unwrap();
        println!();
        rbpf::disassembler::disassemble(&ebpf_prog);

        let mut data: &mut [u8] = &mut [0x11, 0x12, 0x13, 0x14];
        let cr = { Simple::run(&insns, &data).unwrap() };
        let vm = rbpf::EbpfVmRaw::new(&ebpf_prog);
        let er = vm.prog_exec(&mut data);
        assert_eq!(cr, er as u32);
    }

    #[test]
    fn test5() {
        let insns = [
            BpfInsn::new(BPF_LD_IMM, 0, 0, 10),
            BpfInsn::new(BPF_ST, 0, 0, 1),
            BpfInsn::new(BPF_LDX_MEM, 0, 0, 1),
            BpfInsn::new(BPF_MISC_TXA, 0, 0, 0),
            BpfInsn::new(BPF_RET_A, 0, 0, 0),
        ];
        let ebpf_prog = convert(&insns).unwrap();
        println!();
        rbpf::disassembler::disassemble(&ebpf_prog);

        let mut data: &mut [u8] = &mut [0x11, 0x12, 0x13, 0x14];
        let cr = { Simple::run(&insns, &data).unwrap() };
        let vm = rbpf::EbpfVmRaw::new(&ebpf_prog);
        let er = vm.prog_exec(&mut data);
        println!("{}", cr);
        assert_eq!(cr, er as u32);
    }

    #[test]
    fn test6() {
        let insns = [
            BpfInsn::new(BPF_LDX_B_MSH, 0, 0, 0),
            BpfInsn::new(BPF_LD_W_IND, 0, 0, 1),
            BpfInsn::new(BPF_RET_A, 0, 0, 0),
        ];
        let ebpf_prog = convert(&insns).unwrap();
        println!();
        rbpf::disassembler::disassemble(&ebpf_prog);

        let mut data: &mut [u8] = &mut [
            0x2,
            0x1,
            0x2,
            0x3,
            0x4,
            0x5,
            0x6,
            0x7,
            0x8,
            0x12,
            0x34,
            0x56,
            0x78,
            0x9a,
            0xbc,
            0xde,
        ];
        let cr = { Simple::run(&insns, &data).unwrap() };
        let vm = rbpf::EbpfVmRaw::new(&ebpf_prog);
        let er = vm.prog_exec(&mut data);
        println!("0x{:x}", cr);
        assert_eq!(cr, er as u32);
    }

    #[test]
    fn test7() {
        let insns = [
            BpfInsn::new(BPF_LDX_B_MSH, 0, 0, 0),
            BpfInsn::new(BPF_LD_H_IND, 0, 0, 1),
            BpfInsn::new(BPF_RET_A, 0, 0, 0),
        ];
        let ebpf_prog = convert(&insns).unwrap();
        println!();
        rbpf::disassembler::disassemble(&ebpf_prog);

        let mut data: &mut [u8] = &mut [
            0x2,
            0x1,
            0x2,
            0x3,
            0x4,
            0x5,
            0x6,
            0x7,
            0x8,
            0x12,
            0x34,
            0x56,
            0x78,
            0x9a,
            0xbc,
            0xde,
        ];
        let cr = { Simple::run(&insns, &data).unwrap() };
        let vm = rbpf::EbpfVmRaw::new(&ebpf_prog);
        let er = vm.prog_exec(&mut data);
        println!("0x{:x}", cr);
        assert_eq!(cr, er as u32);
    }

    #[test]
    fn test8() {
        let insns = [
            BpfInsn::new(BPF_LDX_B_MSH, 0, 0, 0),
            BpfInsn::new(BPF_LD_B_IND, 0, 0, 1),
            BpfInsn::new(BPF_RET_A, 0, 0, 0),
        ];
        let ebpf_prog = convert(&insns).unwrap();
        println!();
        rbpf::disassembler::disassemble(&ebpf_prog);

        let mut data: &mut [u8] = &mut [
            0x2,
            0x1,
            0x2,
            0x3,
            0x4,
            0x5,
            0x6,
            0x7,
            0x8,
            0x12,
            0x34,
            0x56,
            0x78,
            0x9a,
            0xbc,
            0xde,
        ];
        let cr = { Simple::run(&insns, &data).unwrap() };
        let vm = rbpf::EbpfVmRaw::new(&ebpf_prog);
        let er = vm.prog_exec(&mut data);
        println!("0x{:x}", cr);
        assert_eq!(cr, er as u32);
    }
}
