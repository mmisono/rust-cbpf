/// Compile `cBPF` program using libpcap
extern crate cbpf;
#[macro_use]
extern crate error_chain;
extern crate pcap;
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
#[structopt(name = "cbpf_compile", about = "Compile cBPF program using libpcap")]
struct Opt {
    #[structopt(short = "d", long = "debug", help = "Activate debug mode")] debug: bool,
    #[structopt(short = "o", long = "outfile", help = "Output file")] outfile: String,
    #[structopt(short = "l", long = "linktype", /* default is ethernet */
                help = "LinkType (http://www.tcpdump.org/linktypes.html)", default_value = "1")]
    linktype: i32,
    #[structopt(help = "cBPF filter expression")] expression: String,
}

fn as_raw_bytes<T: ?Sized>(x: &T) -> &[u8] {
    unsafe { std::slice::from_raw_parts(x as *const T as *const u8, std::mem::size_of_val(x)) }
}

fn run() -> Result<()> {
    let args = Opt::from_args();

    let pcap = pcap::Capture::dead(pcap::Linktype(args.linktype))?;
    let bpf_prog = pcap.compile(&args.expression)?;
    // we do this since pcap crate does not expose internal bpf structure
    let insns: &[BpfInsn] = unsafe { std::mem::transmute(bpf_prog.get_instructions()) };

    if args.debug {
        println!("expression: {}", args.expression);
        println!("length: {:?}", insns.len());
        for insn in insns {
            println!("{:?}", insn);
        }
    }

    let mut f = BufWriter::new(fs::File::create(args.outfile)?);
    f.write_all(as_raw_bytes(insns))?;

    Ok(())
}

quick_main!(run);
