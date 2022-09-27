#![no_std]
#![no_main]
#![feature(asm_const)]
#![windows_subsystem = "console"]

use core::arch::asm;
use core::panic::PanicInfo;

// Blow up if we try to compile without msvc, x64 arch, or windows.
#[cfg(not(all(target_env = "msvc", target_arch = "x86_64", target_os = "windows")))]
compile_error!("Platform not supported!");

// Includes syscall constant.
include!(concat!(env!("OUT_DIR"), "/syscall.rs"));

macro_rules! buf {
  () => {
    "Hello World!\n"
  };
}

// Actually this function returns u32 (xor eax, eax; ret)
#[no_mangle]
extern "C" fn mainCRTStartup() {
  unsafe {
    asm!(
      // NtWriteFile (see https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile)
      //
      //  num | type             | name          | register | desc
      // -----|------------------|---------------|----------|---------------------
      //    1 | HANDLE           | FileHandle    | r10      |
      //    2 | HANDLE           | Event         | rdx      | unused
      //    3 | PIO_APC_ROUTINE  | ApcRoutine    | r8       | unused
      //    4 | PVOID            | ApcContext    | r9       | unused
      //    5 | PIO_STATUS_BLOCK | IoStatusBlock | rsp+0x28 | unused (required)
      //    6 | PVOID            | Buffer        | rsp+0x30 |
      //    7 | ULONG            | Length        | rsp+0x38 |
      //    8 | PLARGE_INTEGER   | ByteOffset    | rsp+0x40 | should be 0 at time of syscall
      //    9 | PULONG           | Key           | rsp+0x48 | should be 0 at time of syscall
      //

      //allocate memory
      //stack size = 80 (see https://github.com/JustasMasiulis/inline_syscall/blob/master/include/inline_syscall.inl)
      //If I understand correctly, then the stack size is calculated like this:
      //1. 8 bytes for "pseudo ret address"
      //2. NtWriteFile has 9 args, 9 * 8 = 72 bytes (first 32 bytes is shadow space)
      //3. stack alignment by 16, in our case is nothing to align
      "sub rsp, 80",

      //arg 1, r10 = NtCurrentTeb()->ProcessParameters->hStdOutput
      //most useful structs is described in wine source code
      //see: https://github.com/wine-mirror/wine/blob/master/include/winternl.h
      //r10 = 0x60 (offset to PEB)
      "push 0x60",
      "pop r10",

      //r10 = PEB*
      "mov r10, gs:[r10]",
      //0x20 is RTL_USER_PROCESS_PARAMETERS offset
      "mov r10, [r10 + 0x20]",
      //0x28 is hStdOutput offset
      "mov r10, [r10 + 0x28]",

      //arg 2, rdx = 0
      "xor edx, edx",

      //arg 3, r8 = 0, not necessary
      //"xor r8, r8",

      //arg 4, r9 = 0, not necessary
      //"xor r9, r9",

      //arg 5, [rsp + 0x28]
      //this is not quite correct, but we will just overwrite the memory location
      //called "stack shadow space"
      //see: https://stackoverflow.com/questions/30190132/what-is-the-shadow-space-in-x64-assembly
      //memory from rsp to [rsp + sizeof(IO_STATUS_BLOCK)] will be overwritten after syscall
      //sizeof(IO_STATUS_BLOCK) = 16 bytes
      "mov [rsp + 0x28], rsp",

      //arg 6, [rsp + 0x30]
      //this is dirty hack to save bytes and push string to register rax
      //call instruction will push address of hello world string to the stack and jumps to label 1
      //so, we can store address of string using pop instruction
      //label "1", f - forward (see https://doc.rust-lang.org/nightly/rust-by-example/unsafe/asm.html#labels)
      "call 1f",
      concat!(".ascii \"", buf!(), "\""),
      "1: pop rax",
      "mov [rsp + 0x30], rax",

      //arg 7, [rsp + 0x38]
      "mov dword ptr [rsp + 0x38], {1}",

      //arg 8, [rsp + 0x40], not necessary
      //"mov qword ptr [rsp + 0x40], 0",

      //arg 9, [rsp + 0x48], not necessary
      //"mov qword ptr [rsp + 0x48], 0",

      //eax = NT_WRITE_FILE_SYSCALL_ID
      "push {0}",
      "pop rax",

      //make syscall
      "syscall",

      //eax = 0 (exit code)
      "xor eax, eax",

      //deallocate memory
      "add rsp, 80",
      const NT_WRITE_FILE_SYSCALL_ID,
      const buf!().len(),
      options(nomem, nostack),
    );
  }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
  loop {}
}
