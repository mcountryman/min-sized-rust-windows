use std::slice::from_raw_parts;

use iced_x86::{Code, Decoder, DecoderOptions, OpKind, Register};
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use winapi::um::libloaderapi::{GetProcAddress, LoadLibraryA};

macro_rules! l {
  ($str: expr) => {
    concat!($str, "\0").as_ptr() as *const _
  };
}

fn main() {
  unsafe {
    let id = get_syscall_id(l!("ntdll.dll"), l!("NtWriteFile"));
    match id {
      Some(id) => {
        let path = env::var("OUT_DIR") //
          .expect("Missing environment variable 'OUT_DIR'");
        let path = Path::new(&path).join("syscall.rs");
        let mut f =
          File::create(&path) //
            .unwrap_or_else(|_| panic!("Failed to open file '{:?}'", path));

        writeln!(f, "pub const NT_WRITE_FILE_SYSCALL_ID: u32 = {};", id)
          .unwrap_or_else(|_| panic!("Failed to write to file '{:?}'", path));
      }
      None => panic!("syscall for ntdll.NtWriteFile not found"),
    };
  }
}

/// Try resolve syscall id
unsafe fn get_syscall_id(library: *const i8, name: *const i8) -> Option<u32> {
  let library = LoadLibraryA(library);
  let addr = GetProcAddress(library, name);
  let addr = addr as *const u8;
  let addr = from_raw_parts(addr, 50);

  let mut id = None;
  let mut decoder = Decoder::new(64, addr, DecoderOptions::NONE);

  while decoder.can_decode() {
    let instr = decoder.decode();

    // mov eax, ?
    if instr.op0_register() == Register::EAX {
      id = if instr.op_kind(1) == OpKind::Immediate32 {
        Some(instr.immediate32())
      } else {
        None
      };
    }

    // syscall
    if instr.code() == Code::Syscall {
      return id;
    }
  }

  None
}
