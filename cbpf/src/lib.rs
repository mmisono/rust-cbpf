#![cfg_attr(not(feature = "std"), no_std)]

extern crate byteorder;
#[cfg(feature = "std")]
extern crate core;

pub mod opcode;
pub mod interpreter;

#[cfg(feature = "std")]
pub mod io;

#[derive(Debug, Clone, Copy)]
pub enum Error {
    InvalidInstruction,
    InvalidRval,
    InvalidLdInstruction,
    InvalidSrc,
    InvalidJmpCondition,
    InvalidAluOp,
    InvalidMiscOp,
    DivisionByZero,
    OutOfRange,
    PcOutOfRange,
}

use self::Error::*;

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        match *self {
            InvalidInstruction => write!(f, "invalid cBPF instruction"),
            InvalidRval => write!(f, "invalid return value"),
            InvalidLdInstruction => write!(f, "invalid load instruction"),
            InvalidSrc => write!(f, "invalid src operand"),
            InvalidJmpCondition => write!(f, "invalid jump condition"),
            InvalidAluOp => write!(f, "invaild alu operation"),
            InvalidMiscOp => write!(f, "invaild misc operation"),
            DivisionByZero => write!(f, "devide by zero"),
            OutOfRange => write!(f, "index out of range"),
            PcOutOfRange => write!(f, "program counter out of range"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            InvalidInstruction => "use unknown instruction",
            InvalidRval => "invalid return value",
            InvalidLdInstruction => "invalid load instruction",
            InvalidSrc => "invalid src operand",
            InvalidJmpCondition => "invalid jump condition",
            InvalidAluOp => "invaild alu operation",
            InvalidMiscOp => "invaild misc operation",
            DivisionByZero => "divide by zero",
            OutOfRange => "index out of range",
            PcOutOfRange => "program counter out of range",
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            _ => None,
        }
    }
}
