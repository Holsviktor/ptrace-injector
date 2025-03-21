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
    //regs.rsp -= 8;
    //set_registers(pid, &regs);
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

fn main() {
    // Create child process
    let child = Command::new("echo")
        .args(["Hello"])
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

    // Interrupt process
    // This could've been done using PTRACE_ATTACH rather than SEIZE
    // But I chose to do it this way to verify this function is working properly.
    match interrupt(pid) {
        s if libc::WIFEXITED(s) => panic!("Process exited."),
        s if libc::WIFSIGNALED(s) => panic!("Process signaled."),
        _ => (),
    }

    let section_string : String;
    match std::fs::read_to_string(format!("/proc/{}/maps",pid)) {
        Ok(s) => section_string = s,
        Err(e) => panic!("Error encountered when reading from /proc/{}/maps: {}", pid, e),
    }
    println!("{}", section_string);

    let old_regs : user_regs_struct = get_registers(pid);
    let mut new_regs : user_regs_struct = old_regs;

    new_regs.rbp = old_regs.rsp;
    println!("Old rbp and rsp: {:x}  {:x}", old_regs.rbp, old_regs.rsp);
    println!("New rbp and rsp: {:x}  {:x}", new_regs.rbp, new_regs.rsp);

    println!("Before write: {:x}", read_qword(pid, old_regs.rsp));
    push_to_tracee(pid, 0xdeadbeefdeadbeef);
    println!("After write: {:x}", read_qword(pid, old_regs.rsp));

    resume(pid);

    return;
}
