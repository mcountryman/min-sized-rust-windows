//! # The build script.
//!
//! Provides two functions.
//!
//! 1. Resolves syscall id of `NtWriteFile` of local system and creates a rust file at
//! `$OUT_DIR/syscall.rs` containing a single constant `NT_WRITE_FILE_SYSCALL_ID`.
//!
//! 2. Writes link.exe flags to optimize size.

use std::slice::from_raw_parts;

use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};

/// Converts string literal into a `LPCSTR`
macro_rules! l {
  ($str: expr) => {
    concat!($str, "\0").as_ptr() as *const _
  };
}

fn main() {
  // File alignment flags to reduce size of `.text` section.
  println!("cargo:rustc-link-arg-bins=/ALIGN:8");
  println!("cargo:rustc-link-arg-bins=/FILEALIGN:1");
  // Merges empty `.rdata` and `.pdata` into .text section saving a few bytes in data
  // directories portion  of PE header.
  println!("cargo:rustc-link-arg-bins=/MERGE:.rdata=.text");
  println!("cargo:rustc-link-arg-bins=/MERGE:.pdata=.text");
  // Prevents linking default C runtime libraries.
  println!("cargo:rustc-link-arg-bins=/NODEFAULTLIB");
  // Removes `IMAGE_DEBUG_DIRECTORY` from PE.
  println!("cargo:rustc-link-arg-bins=/EMITPOGOPHASEINFO");
  println!("cargo:rustc-link-arg-bins=/DEBUG:NONE");
  // See: https://github.com/mcountryman/min-sized-rust-windows/pull/7
  println!("cargo:rustc-link-arg-bins=/STUB:stub.exe");

  unsafe {
    // First we find the syscall id of `NtWriteFile`.
    let id = get_syscall_id(l!("ntdll.dll"), l!("NtWriteFile"))
      .expect("syscall for ntdll.NtWriteFile not found");

    // Get `OUT_DIR` path.
    let path = env::var("OUT_DIR").expect("Missing environment variable 'OUT_DIR'");

    // Create file at `$OUT_DIR/syscall.rs`
    let path = Path::new(&path).join("syscall.rs");
    let mut syscall =
      File::create(&path).unwrap_or_else(|_| panic!("Failed to open file '{:?}'", path));

    // Write constant def `NT_WRITE_FILE_SYSCALL_ID`
    writeln!(syscall, "pub const NT_WRITE_FILE_SYSCALL_ID: u32 = {};", id)
      .unwrap_or_else(|_| panic!("Failed to write to file '{:?}'", path));
  }
}

/// Attempt to find syscall id from supplied procedure in supplied library by
/// iterating over instructions until a syscall opcode is found.
unsafe fn get_syscall_id(library: *const i8, name: *const i8) -> Option<u32> {
  // Load the procedure and pull out the first 50b
  let library = LoadLibraryA(library);
  let addr = GetProcAddress(library, name);
  let addr = addr as *const u8;
  let addr = from_raw_parts(addr, 50);

  let mut id = None;
  // Init decoder with hardcoded x64 arch
  let mut decoder = Decoder::new(64, addr, DecoderOptions::NONE);

  // Iterate over instructions
  while decoder.can_decode() {
    let instr = decoder.decode();

    // Find instruction that mov's syscall id into eax register
    // `mov eax, ?`
    if instr.op0_register() == Register::EAX {
      id = if instr.op_kind(1) == OpKind::Immediate32 {
        Some(instr.immediate32())
      } else {
        None
      };
    }

    // Syscall found, return last known eax mov'd operand and
    // hope for the best.
    if instr.code() == Code::Syscall {
      return id;
    }
  }

  None
}
