/// Simple `cBPF` interpreter runner
extern crate cbpf;
#[macro_use]
extern crate error_chain;
extern crate structopt;
#[macro_use]
extern crate structopt_derive;

use cbpf::interpreter::Interpreter;
use structopt::StructOpt;

mod errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
            Cbpf(::cbpf::Error);
        }
    }
}

use errors::*;

#[derive(StructOpt, Debug)]
#[structopt(name = "cbpf_run", about = "Running cBPF program")]
struct Opt {
    #[structopt(short = "d", long = "debug", help = "Activate debug mode")] debug: bool,
    #[structopt(long = "data", help = "Input data")] data_path: Option<String>,
    #[structopt(help = "cBPF program file")] cbpf_path: String,
}

fn run() -> Result<()> {
    let args = Opt::from_args();

    let insns = cbpf::io::read_cbpf(args.cbpf_path)?;

    let data = {
        if let Some(path) = args.data_path {
            cbpf::io::read_data(path)?
        } else {
            vec![]
        }
    };

    let r = cbpf::interpreter::Simple::run(&insns, &data)?;
    println!("{}", r);

    Ok(())
}

quick_main!(run);
