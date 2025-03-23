use libc::{ptrace, waitpid, user_regs_struct, pid_t, c_void};
use std::process::Command;
use std::ptr;

fn get_registers(pid : pid_t) -> user_regs_struct {
    // Gets the registers of process with given pid
    unsafe {
        let mut regs = std::mem::MaybeUninit::<libc::user_regs_struct>::zeroed().assume_init();
        if ptrace(libc::PTRACE_GETREGS, pid, 0, &mut regs) == -1 {
            panic!("failed to get registers");
        }
        regs
    }
}
fn set_registers(pid : pid_t, regs : &user_regs_struct) {
    // Sets the registers of process with given pid
    unsafe {
        ptrace(libc::PTRACE_SETREGS, pid, ptr::null_mut::<i8>(), regs as *const _ as *const _);
    }
}

fn interrupt(pid : pid_t) -> i32 {
    let mut status : i32 = -42;
    unsafe {
        ptrace(libc::PTRACE_INTERRUPT, pid, ptr::null_mut::<i8>(), ptr::null_mut::<i8>());
        waitpid(pid, &mut status, 0);
    }
    status
}
fn resume(pid : pid_t) {
    unsafe {
        ptrace(libc::PTRACE_CONT, pid, ptr::null_mut::<i8>(), ptr::null_mut::<i8>());
    }
}
fn push_to_tracee(pid : pid_t, data : u64) {
    let mut regs : user_regs_struct = get_registers(pid);
    regs.rsp -= 8;
    set_registers(pid, &regs);
    unsafe {
        if ptrace(libc::PTRACE_POKEDATA, pid, regs.rsp as *mut c_void, data as *mut c_void) == -1 {
            panic!("Failed to write data");
        }
    }
}
fn read_qword(pid : pid_t, addr : u64) -> u64 {
    let text : u64;
    unsafe {
        text = ptrace(libc::PTRACE_PEEKDATA, pid, addr as *mut c_void, ptr::null_mut::<u64>()) as u64;
    }
    text
}
fn push_string_to_tracee(pid : pid_t, s : &str) {
    let mut bytestring = s.as_bytes().to_vec();
    bytestring.push(0);

    while bytestring.len() % 8 != 0 {
        bytestring.push(0);
    }

    for chunk in bytestring.chunks_exact(8).rev() {
        let mut word : u64 = 0;

        // Copy bytes into word little-endian style
        for (i, &b) in chunk.iter().enumerate() {
            word |= (b as u64) << (i*8);
        }
        push_to_tracee(pid, word);
    }
}

// Helper function to decode a u64 into a readable string
fn u64_to_string(value: u64) -> String {
    let mut bytes = Vec::new();
    for i in 0..8 {
        let byte = ((value >> (i * 8)) & 0xff) as u8;
        if byte == 0 {
            break;
        }
        bytes.push(byte);
    }
    String::from_utf8_lossy(&bytes).to_string()
}

fn main() {
    // Create child process
    let child = Command::new("/bin/bash")
        .args(["-c", "echo hello"])
        .spawn()
        .expect("failed to start echo");
    let pid = child.id() as pid_t;
    println!("Child pid: {pid}");


    // Attach to child process
    unsafe {
        if ptrace(libc::PTRACE_SEIZE, pid, ptr::null_mut::<i8>(), ptr::null_mut::<i8>()) == -1 {
            eprintln!("Failed to attach to process");
            return;
        }
    }
    println!("Attached to process");

    // Sleep to let the process run load libc
    std::thread::sleep(std::time::Duration::from_millis(1));

    // Interrupt process
    match interrupt(pid) {
        s if libc::WIFEXITED(s) => panic!("Process exited."),
        s if libc::WIFSIGNALED(s) => panic!("Process signaled."),
        _ => (),
    }

    // Read the sections of tracee's memory
    let section_string : String;
    match std::fs::read_to_string(format!("/proc/{}/maps",pid)) {
        Ok(s) => section_string = s,
        Err(e) => panic!("Error encountered when reading from /proc/{}/maps: {}", pid, e),
    }

    // Find libc
    let libc_string_opt = section_string
        .split([' ', '\n'])
        .filter(|s| s.contains("libc.so.6"))
        .collect::<Vec<&str>>();
    let libc_string = match libc_string_opt.get(0) {
        Some(s) => s,
        None => panic!("no libc found"),
    };
    println!("{}", section_string);
    let libc_offset_vec = section_string
        .split('\n')
        .filter(|s| s.contains("libc.so.6"))
        .filter(|s| s.contains("r-xp"))
        .map(|line| line
            .split('-')
            .collect::<Vec<&str>>()
        )
        .collect::<Vec<Vec<&str>>>();

    let libc_offset = match libc_offset_vec
        .get(0)
        .expect("libc found but not in executable.")
        .get(0) {
            Some(s) => {
                match u64::from_str_radix(s, 16) {
                    Ok(u) => u,
                    Err(e) => panic!("Error parsing hex: {}", e),
                }
            },
            None => panic!("libc found but not executable?"),
    };
    println!("libc offset: {:x}", libc_offset);

    // Set up stack frame
    let old_regs : user_regs_struct = get_registers(pid);
    let mut new_regs : user_regs_struct = old_regs;
    let argstring : &str = "ls -l -a this/directory";
    let string_length : u64 = ((argstring.len() + 1) as f64 / 8.0).ceil() as u64;

    push_to_tracee(pid, old_regs.rip);
    push_to_tracee(pid, old_regs.rbp);
    new_regs.rbp = old_regs.rsp - 16;
    push_string_to_tracee(pid, argstring);
    new_regs.rax = old_regs.rsp-16-(string_length*8); // Pointer to start of string

    // Print strings in stack frame
    println!("Stringlength: {:x}", string_length);
    for i in 3..(string_length + 3) {
        println!("rsp-{} | {:x}: \x1b[32m{}\x1b[0m", i*8, new_regs.rsp-8*i, u64_to_string(read_qword(pid,new_regs.rsp-8*i)));
    }
    println!("Start of string at: \x1b[31m{:x}\x1b[0m", new_regs.rax);


    resume(pid);

    return;
}
