extern crate std;

use opcode::BpfInsn;

use std::fs::File;
use std::path::Path;
use std::io::{Read, Result};

/// read `cBPF` file from path
pub fn read_cbpf<I>(path: I) -> Result<Vec<BpfInsn>>
where
    I: AsRef<Path>,
{
    let mut buf = vec![];
    File::open(path)?.read_to_end(&mut buf)?;

    println!("{:?}", buf);

    if buf.len() % std::mem::size_of::<BpfInsn>() != 0 {
        println!("data size is invalid");
        panic!();
    }

    // cast buf to array of BpfInsn
    let len = buf.len() / std::mem::size_of::<BpfInsn>();
    let data = Box::into_raw(buf.into_boxed_slice()) as *mut u8;
    let r = unsafe {
        let s = std::slice::from_raw_parts_mut(data, len) as *mut [u8] as *mut [BpfInsn];
        let b = &mut *s;
        Box::from_raw(b).into_vec()
    };

    // XXX: we should verify the program, but we don't have a verifier yet

    Ok(r)
}

pub fn read_data<I>(path: I) -> Result<Vec<u8>>
where
    I: AsRef<Path>,
{
    let mut buf = vec![];
    File::open(path)?.read_to_end(&mut buf)?;

    Ok(buf)
}
