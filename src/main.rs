#[macro_use]
extern crate error_chain;
extern crate libc;
extern crate nix;
extern crate potential_couscous;

use std::env;
use std::ffi;

error_chain! {
    foreign_links {
        UnixError(nix::Error);
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
