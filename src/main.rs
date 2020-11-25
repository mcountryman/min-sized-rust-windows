#![no_std]
#![no_main]
#![feature(asm)]
#![windows_subsystem = "console"]

mod types;

use core::mem::transmute;
use core::ptr::null_mut;

use core::panic::PanicInfo;

use ntapi::winapi_local::um::winnt::NtCurrentTeb;

use crate::types::{LDR_DATA_TABLE_ENTRY, PEB, PEB_LDR_DATA};
use core::mem::MaybeUninit;
use winapi::ctypes::c_void;
use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::LIST_ENTRY;
use winapi::um::winnt::{
  HANDLE, IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE,
  IMAGE_EXPORT_DIRECTORY, IMAGE_NT_HEADERS64, IMAGE_NT_OPTIONAL_HDR_MAGIC,
  IMAGE_NT_SIGNATURE, PIMAGE_DOS_HEADER, PIMAGE_NT_HEADERS,
};

pub type c_int = i32;
pub type c_char = i8;

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
  loop {}
}

type GetStdHandleFn = extern "system" fn(std_handle: DWORD) -> HANDLE;
type WriteFileFn = extern "system" fn(
  handle: HANDLE,
  buf: *const u8,
  buf_len: usize,
  buf_read: *mut usize,
  buf_overlapped: *mut usize,
) -> ();

#[no_mangle]
extern "C" fn _mainCRTStartup() {
  unsafe {
    let peb = MaybeUninit::<PEB>::uninit();
    asm!("mov {}, gs:[0x60]", out(reg) peb);
    let ldr: *mut PEB_LDR_DATA = peb.assume_init().Ldr;
    let lst = (*ldr).InLoadOrderModuleList;

    let kernel_32 = (*(*lst.Flink).Flink).Flink;
    let get_std_handle = get_export_fn::<GetStdHandleFn>(kernel_32, "GetStdHandle")
      .expect("GetStdHandle not found");
    let get_std_handle: GetStdHandleFn = transmute(get_std_handle);
    let write_file = get_export_fn::<WriteFileFn>(kernel_32, "WriteFile") //
      .expect("WriteFile not found");
    let write_file: WriteFileFn = transmute(write_file);

    let buf = b"Hello World!\n\0\0\0\0\0";
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

unsafe fn get_export_fn<U: Sized>(
  entry: *mut LIST_ENTRY,
  import: &str,
) -> Option<*const c_void> {
  let entry = entry as *mut LDR_DATA_TABLE_ENTRY;
  let base = (*entry).DllBase as *mut c_char;

  let dos_header: PIMAGE_DOS_HEADER = base as *mut IMAGE_DOS_HEADER;
  let dos_header = *dos_header;
  if dos_header.e_magic != IMAGE_DOS_SIGNATURE {
    panic!("Bad dos header signature");
  }

  let nt_header: PIMAGE_NT_HEADERS =
    base.offset(dos_header.e_lfanew as isize) as *mut IMAGE_NT_HEADERS64;
  let nt_header = *nt_header;
  if nt_header.Signature != IMAGE_NT_SIGNATURE {
    panic!("Bad nt header signature");
  }

  let optional_header = nt_header.OptionalHeader;
  if optional_header.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC {
    panic!("Bad optional header signature");
  }

  let export = optional_header.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
  let export = export.VirtualAddress as usize;
  let export = base.add(export);
  let export = export as *mut IMAGE_EXPORT_DIRECTORY;

  let export_addrs = base.add((*export).AddressOfFunctions as usize) as *const u32;
  let export_names = base.add((*export).AddressOfNames as usize) as *const u32;
  let export_ords = base.add((*export).AddressOfNameOrdinals as usize) as *const u16;

  for i in 0..(*export).NumberOfNames as usize {
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

unsafe fn is_eq(lhs: *mut c_char, rhs: &str) -> bool {
  let mut i = 0;
  let rhs_len = rhs.len();
  let mut rhs_inner = rhs.chars();

  loop {
    let lhs_c = *lhs.add(i) as u8;
    if lhs_c == b'\0' {
      return i == rhs_len;
    }

    let rhs_c = rhs_inner.next();
    if let Some(rhs_c) = rhs_c {
      if lhs_c != rhs_c as u8 {
        return false;
      }
    };

    i += 1;
  }
}
