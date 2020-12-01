#![cfg_attr(not(debug_assertions), no_std)]
#![cfg_attr(not(debug_assertions), no_main)]
#![feature(asm)]
#![feature(link_args)]
#![windows_subsystem = "console"]

use core::mem::transmute;
#[cfg(not(debug_assertions))]
use core::panic::PanicInfo;
use core::ptr::null_mut;

use winapi::ctypes::c_void;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::LIST_ENTRY;
use winapi::um::winnt::{
  HANDLE, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY,
  IMAGE_NT_HEADERS, PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS,
};

use crate::types::{LDR_DATA_TABLE_ENTRY, PEB, PEB_LDR_DATA};

mod types;

#[allow(non_camel_case_types)]
pub type c_int = i32;
#[allow(non_camel_case_types)]
pub type c_char = i8;

type GetStdHandleFn = extern "system" fn(std_handle: DWORD) -> HANDLE;
type WriteFileFn = extern "system" fn(
  handle: HANDLE,
  buf: *const u8,
  buf_len: usize,
  buf_read: *mut usize,
  buf_overlapped: *mut usize,
) -> ();

#[cfg(not(debug_assertions))]
#[no_mangle]
extern "C" fn mainCRTStartup() -> u32 {
  main();
  0
}

fn main() {
  unsafe {
    let peb = get_peb();
    let ldr: *mut PEB_LDR_DATA = (*peb).Ldr;
    let lst = (*ldr).InLoadOrderModuleList;

    // .InLoadOrderModuleList contains the following in order
    // 1. `min-sized-rust.exe`
    // 2. `ntdll.dll`
    // 3. `kernel32.dll`
    // ...
    let kernel_32 = (*(*lst.Flink).Flink).Flink;

    // Resolve `kernel32.GetStdHandle`
    let get_std_handle =
      get_export_fn::<GetStdHandleFn>(kernel_32, b"GetStdHandle\0").unwrap();
    let get_std_handle: GetStdHandleFn = transmute(get_std_handle);

    // Resolve `kernel32.WriteFile`
    let write_file = get_export_fn::<WriteFileFn>(kernel_32, b"WriteFile\0") //
      .unwrap();
    let write_file: WriteFileFn = transmute(write_file);

    let buf = b"Hello World!\n";
    let mut read = 0usize;

    let handle = get_std_handle(-11i32 as DWORD);
    (write_file)(
      handle,
      buf.as_ptr(),
      buf.len(),
      &mut read as *mut _,
      null_mut(),
    );
  }
}

/// Resolve ptr to `PEB`.
unsafe fn get_peb() -> *mut PEB {
  let peb: *mut PEB;

  #[cfg(target_arch = "x86")]
  asm!(
    "mov {}, fs:[0x30]",
    out(reg) peb,
  );

  #[cfg(target_arch = "x86_64")]
  asm!(
    "mov {}, gs:[0x60]",
    out(reg) peb,
  );

  // just ignore this "uinitialized" value here..
  peb
}

/// Resolve export addr from `LIST_ENTRY` by name using supplied `import`.
unsafe fn get_export_fn<U: Sized>(
  entry: *mut LIST_ENTRY,
  import: &[u8],
) -> Option<*const c_void> {
  let entry = entry as *mut LDR_DATA_TABLE_ENTRY;
  let base = (*entry).DllBase as *mut c_char;

  // Get IMAGE_DOS_HEADER
  let dos_header: PIMAGE_DOS_HEADER = base as *mut IMAGE_DOS_HEADER;
  let dos_header = *dos_header;

  // Get IMAGE_NT_HEADERS
  let nt_header: PIMAGE_NT_HEADERS =
    base.offset(dos_header.e_lfanew as isize) as *mut IMAGE_NT_HEADERS;
  let nt_header = *nt_header;

  // Get IMAGE_OPTIONALHEADERS
  let optional_header = nt_header.OptionalHeader;

  // Resolve `IMAGE_EXPORT_DIRECTORY` from optional `DataDirectory` index
  let export = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
  let export = export.VirtualAddress as usize;
  let export = base.add(export);
  let export = export as *mut IMAGE_EXPORT_DIRECTORY;

  let export_addrs = base.add((*export).AddressOfFunctions as usize) as *const u32;
  let export_names = base.add((*export).AddressOfNames as usize) as *const u32;
  let export_ords = base.add((*export).AddressOfNameOrdinals as usize) as *const u16;

  // Iterate over exports (probably didn't save anything by inf. loop here :shrug:)
  for i in 0.. {
    // Resolve name VA using RVA index
    let name = *export_names.add(i);
    let name = transmute(base.add(name as usize));

    if strcmp(name, import) {
      // Resolve ordinal
      let ord = *export_ords.add(i);
      // Resolve export addr VA from RVA using ordinal
      let addr = *export_addrs.add(ord as usize);
      let addr = base.add(addr as usize) as *mut c_void;

      return Some(addr);
    }
  }

  None
}

/// Simple strcmp
unsafe fn strcmp(lhs: *mut c_char, rhs: &[u8]) -> bool {
  let mut rhs = rhs.as_ptr();
  let mut lhs = lhs as *mut u8;

  while *rhs != 0 && *lhs != 0 && *rhs == *lhs {
    rhs = rhs.add(1);
    lhs = lhs.add(1);
  }

  *rhs == *lhs
}

/// Magic linker flags to merge sections and prevent linking _anything_
#[allow(unused_attributes)]
#[cfg(not(debug_assertions))]
#[cfg(target_env = "msvc")]
#[link_args = "/MERGE:.rdata=.text /MERGE:.pdata=.text /NODEFAULTLIB"]
extern "C" {}

#[cfg(not(debug_assertions))]
#[panic_handler]
fn panic(_: &PanicInfo) -> ! {
  loop {}
}
