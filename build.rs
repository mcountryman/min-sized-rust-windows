use std::slice::from_raw_parts;

use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};

/// Helper macro for creating null terminated string pointers
macro_rules! l {
  ($str: expr) => {
    concat!($str, "\0").as_ptr() as *const _
  };
}

fn main() {
  // Magic linker flags to merge sections and prevent linking _anything_
  let link_args = &[
    "/ALIGN:8",
    "/FILEALIGN:1",
    "/MERGE:.rdata=.text",
    "/MERGE:.pdata=.text",
    "/NODEFAULTLIB",
    "/EMITPOGOPHASEINFO",
    "/DEBUG:NONE",
    "/STUB:stub.exe",
  ];

  for arg in link_args {
    println!("cargo:rustc-link-arg-bins={}", arg);
  }

  unsafe {
    let id = get_syscall_id(l!("ntdll.dll"), l!("NtWriteFile"));
    match id {
      Some(id) => {
        // Resolve `OUT_DIR`
        let path = env::var("OUT_DIR") //
          .expect("Missing environment variable 'OUT_DIR'");
        
        // Create file at `$OUT_DIR/syscall.rs`
        let path = Path::new(&path).join("syscall.rs");
        let mut f =
          File::create(&path) //
            .unwrap_or_else(|_| panic!("Failed to open file '{:?}'", path));

        // Write constant def `NT_WRITE_FILE_SYSCALL_ID`
        writeln!(f, "pub const NT_WRITE_FILE_SYSCALL_ID: u32 = {};", id)
          .unwrap_or_else(|_| panic!("Failed to write to file '{:?}'", path));
      }
      None => panic!("syscall for ntdll.NtWriteFile not found"),
    };
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
