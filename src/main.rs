use libc::{ptrace, waitpid, user_regs_struct, pid_t};
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
fn test_exec(pid : pid_t) {
        interrupt(pid);
        let mut regs = get_registers(pid);
        println!("rax: {}", regs.rax as u64);
        set_registers(pid, &regs);
        resume(pid);
}

fn main() {
    // Create child process
    let child = Command::new("echo")
        .args(["Hello", "World!"])
        .spawn()
        .expect("failed to start sleep");
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

    test_exec(pid);
    return;
}
