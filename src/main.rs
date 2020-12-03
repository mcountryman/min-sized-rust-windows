#![no_std]
#![no_main]
#![feature(asm)]
#![feature(link_args)]
#![feature(naked_functions)]
#![windows_subsystem = "console"]

use crate::types::PEB;
#[cfg(not(debug_assertions))]
use core::panic::PanicInfo;
use ntapi::ntioapi::IO_STATUS_BLOCK;

mod types;

pub const BUF: &[u8] = b"Hello World!\n\0";

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
      // ZwWriteFile(
      //    HANDLE           FileHandle,    // rcx
      //    HANDLE           Event,         // rdx
      //    PIO_APC_ROUTINE  ApcRoutine,    // r8
      //    PVOID            ApcContext,    // r9
      //    PIO_STATUS_BLOCK IoStatusBlock, // rsp+0x28
      //    PVOID            Buffer,        // rsp+0x30
      //    ULONG            Length,        // rsp+0x38
      //    PLARGE_INTEGER   ByteOffset,    // rsp+0x40 - should be 0 at time of syscall
      //    PULONG           Key            // rsp+0x48 - should be 0 at time of syscall
      //  )

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

      in(reg) &mut status,
      in(reg) BUF.as_ptr(),
      const BUF.len() as u32,

      in("rcx") handle,
      in("rdx") 0,
      in("r8") 0,
      in("r9") 0,
    );

    0
  }
}

/// Magic linker flags to merge sections and prevent linking _anything_
#[allow(unused_attributes)]
#[cfg(not(debug_assertions))]
#[cfg(target_env = "msvc")]
#[link_args = "/ALIGN:8 /FILEALIGN:1 /MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB"]
extern "C" {}

#[cfg(not(debug_assertions))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
  loop {}
}
