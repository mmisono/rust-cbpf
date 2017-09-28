extern crate c2e;
/// Convert cbpf program to ebpf from libpcap's expression
extern crate cbpf;
#[macro_use]
extern crate error_chain;
extern crate pcap;
extern crate rbpf;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;

use std::fs;
use std::io::{BufWriter, Write};
use cbpf::opcode::BpfInsn;
use structopt::StructOpt;

mod errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
            Pcap(::pcap::Error);
        }
    }
}

use errors::*;

#[derive(StructOpt, Debug)]
#[structopt(name = "c2e", about = "Convert cBPF program to eBPF from libpcap's expression")]
struct Opt {
    #[structopt(short = "d", long = "debug", help = "Activate debug mode")] debug: bool,
    #[structopt(short = "o", long = "outfile", help = "Output file")] outfile: String,
    #[structopt(short = "l", long = "linktype", /* default is ethernet */
                help = "LinkType (http://www.tcpdump.org/linktypes.html)", default_value = "1")]
    linktype: i32,
    #[structopt(help = "cBPF filter expression")] expression: String,
}

fn run() -> Result<()> {
    let args = Opt::from_args();

    let pcap = pcap::Capture::dead(pcap::Linktype(args.linktype))?;
    let bpf_prog = pcap.compile(&args.expression)?;
    // we do this since pcap crate does not expose internal bpf structure
    let insns: &[BpfInsn] = unsafe { std::mem::transmute(bpf_prog.get_instructions()) };

    let ebpf_prog = c2e::converter::convert(&insns).unwrap();
    if args.debug {
        println!("expression: {}", args.expression);
        println!("length: {:?}", insns.len());
        println!("cBPF program:");
        for insn in insns {
            println!("{:?}", insn);
        }
        println!();
        println!("eBPF program:");
        rbpf::disassembler::disassemble(&ebpf_prog);
    }

    let mut f = BufWriter::new(fs::File::create(args.outfile)?);
    f.write_all(&ebpf_prog)?;

    Ok(())
}

quick_main!(run);
