#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use winapi::shared::ntdef::{BOOLEAN, LIST_ENTRY, ULONG, NTSTATUS, PULONG};
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

#[repr(C)]
pub struct IO_STATUS_BLOCK {
  _1: IO_STATUS_BLOCK_u,
  _2: PULONG,
}

#[repr(C)]
pub union IO_STATUS_BLOCK_u {
  _1: NTSTATUS,
  _2: PVOID,
}