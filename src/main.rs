extern crate byteorder;
extern crate capstone;
extern crate elf;
#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate nix;
extern crate potential_couscous;

use std::env;
use std::ffi;
use byteorder::WriteBytesExt;
use capstone::prelude::*;

error_chain! {
    foreign_links {
        UnixError(nix::Error);
        CapstoneError(capstone::Error);
    }
}

fn run(binpath: &str) -> Result<()> {
    match nix::unistd::fork()? {
        nix::unistd::ForkResult::Parent { child, .. } => {
            let status = nix::sys::wait::waitpid(child, None)?;
            println!("parent: status: {:#?}", status);

            let ret = nix::sys::ptrace::ptrace(
                nix::sys::ptrace::ptrace::PTRACE_PEEKUSER,
                child,
                (libc::ORIG_RAX * 8) as *mut nix::libc::c_void,
                std::ptr::null_mut(),
            )?;
            println!("parent: ptrace return: {:#?}", ret);

            let cs = Capstone::new()
                .x86()
                .mode(arch::x86::ArchMode::Mode64)
                .syntax(arch::x86::ArchSyntax::Intel)
                .detail(true)
                .build()?;
            
            loop {
                let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
                let p_regs: *mut libc::c_void = &mut regs as *mut _ as *mut libc::c_void;

                nix::sys::ptrace::ptrace(
                    nix::sys::ptrace::ptrace::PTRACE_GETREGS,
                    child,
                    std::ptr::null_mut(),
                    p_regs
                )?;

                //println!("parent: ptrace return: {}", ret);
                println!("parent: RIP: 0x{:X}", regs.rip);

                let instr = nix::sys::ptrace::ptrace(
                    nix::sys::ptrace::ptrace::PTRACE_PEEKTEXT,
                    child,
                    regs.rip as *mut nix::libc::c_void,
                    std::ptr::null_mut()
                )?;

                let mut wtr = vec![];
                wtr.write_i64::<byteorder::LittleEndian>(instr).unwrap();

                //println!("parent: INSTR: {:#?}", instr);
                println!("parent: Bytes: {:#?}", wtr);

                let instructions = cs.disasm_count(wtr.as_slice(), regs.rip, 1)?;

                //println!("parent: found {} instructions", instructions.len());

                if instructions.len() > 0 {
                    let insn = instructions.iter().next().unwrap();
                    println!("{} {}", insn.mnemonic().unwrap(), insn.op_str().unwrap());
                }

                nix::sys::ptrace::ptrace(
                    nix::sys::ptrace::ptrace::PTRACE_SINGLESTEP,
                    child,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )?;
                //println!("parent: ptrace return: {:#?}", ret);
            
                nix::sys::wait::waitpid(child, None)?;
                //println!("parent: status: {:#?}", status);
            }
        }

        nix::unistd::ForkResult::Child => {
            let ret = nix::sys::ptrace::ptrace(
                nix::sys::ptrace::ptrace::PTRACE_TRACEME,
                nix::unistd::Pid::from_raw(0),
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )?;
            println!("child: TRACEME worked: {:#?}", ret);
            nix::unistd::execvp(&ffi::CString::new(binpath).unwrap(), &[])?;
        }
    };
    Ok(())
}

fn _main() -> Result<()> {
    let args: Vec<String> = env::args().collect();

    if args.len() == 2 {
        run(&args[1])?;
    } else {
        println!("Parameters NOK");
    }
    Ok(())
}

quick_main!(_main);
