#![no_std]
#![no_main]
#![feature(asm)]
#![feature(link_args)]
#![windows_subsystem = "console"]

use core::panic::PanicInfo;

use crate::types::{IO_STATUS_BLOCK, PEB};

mod types;

pub const BUF: &[u8] = b"Hello World!\n";

#[no_mangle]
extern "C" fn mainCRTStartup() -> u32 {
  unsafe {
    let peb: *mut PEB;
    let mut status: IO_STATUS_BLOCK = core::mem::zeroed();

    // Get PEB from reserved register `GS`
    asm!(
      "mov {}, gs:[0x60]",
      out(reg) peb,
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
      "mov qword ptr ss:[rsp+0x28], {0}",
      // move buffer ptr into stack
      "mov qword ptr ss:[rsp+0x30], {1}",
      // move buffer len into stack
      "mov qword ptr ss:[rsp+0x38], {2}",

      // clear r8 register
      "mov r8, 0",
      // required for ZwWriteFile on win10
      "mov r10, rcx",
      // syscall index
      "mov eax, 8",
      "syscall",

      // arg 5
      in(reg) &mut status,
      // arg 6
      in(reg) BUF.as_ptr(),
      // arg 7
      const BUF.len() as u32,

      // arg 1
      in("rcx") handle,
      // arg 2
      in("rdx") 0,
      // arg 3
      in("r8") 0,
      // arg 4
      in("r9") 0,
    );

    0
  }
}

/// Magic linker flags to merge sections and prevent linking _anything_
#[allow(unused_attributes)]
#[cfg(target_env = "msvc")]
#[link_args = "/ALIGN:8 /FILEALIGN:1 /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB"]
extern "C" {}

#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
  loop {}
}
