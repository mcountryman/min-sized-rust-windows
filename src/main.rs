#![no_std]
#![no_main]
#![feature(asm_const)]
#![windows_subsystem = "console"]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::panic::PanicInfo;
use core::arch::asm;
use core::mem::MaybeUninit;
use winapi::shared::ntdef::{BOOLEAN, LIST_ENTRY, NTSTATUS, PULONG, ULONG};
use winapi::um::winnt::{HANDLE, PVOID};

// Blow up if we try to compile without msvc, x64 arch, or windows.
#[cfg(not(all(target_env = "msvc", target_arch = "x86_64", target_os = "windows")))]
compile_error!("Platform not supported!");

// Includes syscall constant.
include!(concat!(env!("OUT_DIR"), "/syscall.rs"));

/// The `Hello World!` utf8 buffer.
pub const BUF: &[u8] = b"Hello World!\n";

#[no_mangle]
extern "C" fn mainCRTStartup() -> u32 {
  let peb: *mut PEB;
  let mut status: MaybeUninit<IO_STATUS_BLOCK> = MaybeUninit::uninit();
  unsafe {
    // Get PEB from reserved register `GS`
    asm!(
      "mov {}, gs:[0x60]",
      out(reg) peb,
      options(pure, nomem, nostack)
    );

    // Get STDOUT handle from PEB
    let handle = (*(*peb).ProcessParameters).StandardOutput;

    asm!(
      // ZwWriteFile
      //
      //  num | type             | name          | register | desc
      // -----|------------------|---------------|----------|---------------------
      //    1 | HANDLE           | FileHandle    | rcx      |
      //    2 | HANDLE           | Event         | rdx      | unused
      //    3 | PIO_APC_ROUTINE  | ApcRoutine    | r8       | unused
      //    4 | PVOID            | ApcContext    | r9       | unused
      //    5 | PIO_STATUS_BLOCK | IoStatusBlock | rsp+0x28 | unused (required)
      //    6 | PVOID            | Buffer        | rsp+0x30 |
      //    7 | ULONG            | Length        | rsp+0x38 |
      //    8 | PLARGE_INTEGER   | ByteOffset    | rsp+0x40 | should be 0 at time of syscall
      //    9 | PULONG           | Key           | rsp+0x48 | should be 0 at time of syscall
      //

      // move status ptr into stack
      "mov qword ptr [rsp+0x28], {0}",
      // move buffer ptr into stack
      "mov qword ptr [rsp+0x30], {1}",
      // move buffer len into stack
      "mov dword ptr [rsp+0x38], {2}",

      "syscall",

      // arg 5
      in(reg) &mut status,
      // arg 6
      in(reg) BUF.as_ptr(),
      // arg 7
      const BUF.len() as u32,

      // syscall id
      in("eax") NT_WRITE_FILE_SYSCALL_ID,

      // arg 1
      //in("rcx") handle,
      // on windows 10 the kernel reads from r10 not rcx
      in("r10") handle,
      // arg 2
      in("rdx") 0,
    );

    0
  }
}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
  loop {}
}

#[repr(C)]
pub struct PEB {
  pub InheritedAddressSpace: BOOLEAN,
  pub ReadImageFileExecOptions: BOOLEAN,
  pub BeingDebugged: BOOLEAN,
  pub BitField: BOOLEAN,
  pub Mutant: HANDLE,
  pub ImageBaseAddress: PVOID,
  pub Ldr: *mut PEB_LDR_DATA,
  pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
}

#[repr(C)]
pub struct PEB_LDR_DATA {
  pub Length: ULONG,
  pub Initialized: BOOLEAN,
  pub SsHandle: HANDLE,
  pub InLoadOrderModuleList: LIST_ENTRY,
  // ...
}

#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
  pub MaximumLength: ULONG,
  pub Length: ULONG,
  pub Flags: ULONG,
  pub DebugFlags: ULONG,
  pub ConsoleHandle: HANDLE,
  pub ConsoleFlags: ULONG,
  pub StandardInput: HANDLE,
  pub StandardOutput: HANDLE,
  pub StandardError: HANDLE,
}

#[repr(C)]
pub struct IO_STATUS_BLOCK {
  _1: IO_STATUS_BLOCK_u,
  _2: PULONG,
}

#[repr(C)]
pub union IO_STATUS_BLOCK_u {
  _1: NTSTATUS,
  _2: PVOID,
}
