#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use winapi::shared::ntdef::{BOOLEAN, LIST_ENTRY, ULONG};
use winapi::um::winnt::{HANDLE, PVOID};

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
pub union LDR_DATA_TABLE_ENTRY_u1 {
  InInitializationOrderLinks: LIST_ENTRY,
  InProgressLinks: LIST_ENTRY,
}

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
  pub InLoadOrderLinks: LIST_ENTRY,
  pub InMemoryOrderLinks: LIST_ENTRY,
  pub u1: LDR_DATA_TABLE_ENTRY_u1,
  pub DllBase: PVOID,
  // ...
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
