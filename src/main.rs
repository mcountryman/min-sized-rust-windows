#![cfg_attr(not(debug_assertions), no_std)]
#![cfg_attr(not(debug_assertions), no_main)]
#![feature(llvm_asm)]
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

    let kernel_32 = (*(*lst.Flink).Flink).Flink;
    let get_std_handle =
      get_export_fn::<GetStdHandleFn>(kernel_32, b"GetStdHandle\0").unwrap();
    let get_std_handle: GetStdHandleFn = transmute(get_std_handle);
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

unsafe fn get_peb() -> *mut PEB {
  #[cfg(target_arch = "x86_64")]
  let off: u64;

  #[cfg(target_arch = "x86_64")]
  llvm_asm!(
    "mov $0, gs:[$1]"
    : "=r"(off)
    : "ri"(0x60)
    :
    : "intel"
  );

  off as *mut PEB
}

unsafe fn get_export_fn<U: Sized>(
  entry: *mut LIST_ENTRY,
  import: &[u8],
) -> Option<*const c_void> {
  let entry = entry as *mut LDR_DATA_TABLE_ENTRY;
  let base = (*entry).DllBase as *mut c_char;

  let dos_header: PIMAGE_DOS_HEADER = base as *mut IMAGE_DOS_HEADER;
  let dos_header = *dos_header;

  let nt_header: PIMAGE_NT_HEADERS =
    base.offset(dos_header.e_lfanew as isize) as *mut IMAGE_NT_HEADERS;
  let nt_header = *nt_header;

  let optional_header = nt_header.OptionalHeader;

  let export = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
  let export = export.VirtualAddress as usize;
  let export = base.add(export);
  let export = export as *mut IMAGE_EXPORT_DIRECTORY;

  let export_addrs = base.add((*export).AddressOfFunctions as usize) as *const u32;
  let export_names = base.add((*export).AddressOfNames as usize) as *const u32;
  let export_ords = base.add((*export).AddressOfNameOrdinals as usize) as *const u16;

  for i in 0.. {
    let name = *export_names.add(i);
    let name = transmute(base.add(name as usize));
    if is_eq(name, import) {
      let ord = *export_ords.add(i);
      let addr = *export_addrs.add(ord as usize);
      let addr = base.add(addr as usize) as *mut c_void;

      return Some(addr);
    }
  }

  None
}

unsafe fn is_eq(lhs: *mut c_char, rhs: &[u8]) -> bool {
  let mut rhs = rhs.as_ptr();
  let mut lhs = lhs as *mut u8;

  while *rhs != 0 && *lhs != 0 && *rhs == *lhs {
    rhs = rhs.add(1);
    lhs = lhs.add(1);
  }

  return *rhs == *lhs;
}

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
