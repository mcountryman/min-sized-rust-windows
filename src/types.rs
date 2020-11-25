use winapi::shared::ntdef::{BOOLEAN, LIST_ENTRY, ULONG, UNICODE_STRING, USHORT};
use winapi::um::winnt::{HANDLE, PVOID};

#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY_u1 {
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
