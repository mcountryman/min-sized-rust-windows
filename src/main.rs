#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::arch::naked_asm;
use core::panic::PanicInfo;

// Blow up if we try to compile without msvc, x64 arch, or windows.
#[cfg(not(all(target_env = "msvc", target_arch = "x86_64", target_os = "windows")))]
compile_error!("Platform not supported!");

// Includes syscall constant.
include!(concat!(env!("OUT_DIR"), "/syscall.rs"));

macro_rules! buf {
  () => {
    "Hello World!"
  };
}

#[unsafe(naked)]
#[unsafe(no_mangle)]
unsafe extern "C" fn mainCRTStartup() -> u32 {
  naked_asm!(
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

    //arg 1, r10 = NtCurrentTeb()->ProcessParameters->hStdOutput
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

    //arg 3, r8 = 0, unused (OS loader sets this to 0)
    // "xor r8, r8"

    //arg 4, r9 = 0, unused (OS loader sets this to 0)
    // "xor r9, r9",

    //arg 9, [rsp + 0x48] = 0
    "push rdx",

    //arg 8, [rsp + 0x40] = 0
    //This and Arg 9 will serve as IoStatusBlock
    "push rdx",

    //arg 7, [rsp + 0x38] = Length
    "push {1}",

    //arg 6, [rsp + 0x30] = Buffer
    "call 2f",
    concat!(".ascii \"", buf!(), "\""),
    //new line
    ".byte 0x0a",
    "2:",

    //arg 5, [rsp + 0x28] = IoStatusBlock
    //Overlap Arg 5 (IoStatusBlock pointer) to point to Arg 6 (Buffer Ptr)
    //This overwrites the Buffer Ptr and Length arguments on completion, but saves bytes.
    "push rsp",

    //Allocate shadow space (32 bytes) + alignment padding (8 bytes)
    "sub rsp, 40",

    //shadow space (32 bytes) + alignment (8 bytes)
    //already allocated

    //eax = NT_WRITE_FILE_SYSCALL_ID
    "push {0}",
    "pop rax",

    //make syscall
    "syscall",

    //eax = NtWriteFile return code (STATUS_SUCCESS = 0)
    // "xor eax, eax",

    //deallocate memory (5 args * 8 + 40 shadow = 80 bytes)
    "add rsp, 80",
    "ret",
    const NT_WRITE_FILE_SYSCALL_ID,
    const buf!().len() + 1,
  );
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
  loop {}
}
