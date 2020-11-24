// #![no_std]
// #![no_main]
#![feature(asm)]
// #![feature(alloc_error_handler)]
#![windows_subsystem = "console"]

use core::mem::transmute;

use ntapi::ntldr::LDR_DATA_TABLE_ENTRY;
use ntapi::ntpebteb::TEB;
use ntapi::winapi_local::um::winnt::NtCurrentTeb;
use std::ffi::CStr;
use winapi::um::dbghelp::ImageRvaToVa;
use winapi::um::winnt::{
    IMAGE_DIRECTORY_ENTRY_EXPORT, IMAGE_DIRECTORY_ENTRY_IMPORT, IMAGE_EXPORT_DIRECTORY,
    PIMAGE_DOS_HEADER, PIMAGE_EXPORT_DIRECTORY, PIMAGE_NT_HEADERS, PIMAGE_OPTIONAL_HEADER,
    PIMAGE_SECTION_HEADER,
};

pub type c_int = i32;
pub type c_char = i8;

// #[panic_handler]
// fn panic(info: &PanicInfo) -> ! {
//     loop {}
// }

fn main() {
    unsafe {
        let teb: *mut TEB = unsafe { NtCurrentTeb() };
        let peb = (*teb).ProcessEnvironmentBlock;
        let ldr = (*peb).Ldr;
        let lst = (*ldr).InLoadOrderModuleList;

        let ntdll = (*lst.Flink).Flink;
        let ntdll: *const LDR_DATA_TABLE_ENTRY = transmute(ntdll);
        let ntdll = (*ntdll).DllBase;
        let ntdll_dos: PIMAGE_DOS_HEADER = transmute(ntdll);
        let ntdll_nt: PIMAGE_NT_HEADERS = transmute(ntdll.add((*ntdll_dos).e_lfanew as usize));
        let ntdll_opt = (*ntdll_nt).OptionalHeader;

        let export = ntdll_opt.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT as usize];
        let export = export.VirtualAddress;
        let export = ntdll.add(export as usize);
        let export: PIMAGE_EXPORT_DIRECTORY = transmute(export);
        let export_addrs: *const u32 = transmute(export.add((*export).AddressOfFunctions as usize));
        let export_names: *const u32 = transmute(export.add((*export).AddressOfNames as usize));

        for i in 0..(*export).NumberOfNames as usize {
            let name = *export_addrs.add(i);
            let name = transmute(ntdll.add(name as usize));
            let name = CStr::from_ptr(name);

            println!("{:?}", name);
        }
    }
}
