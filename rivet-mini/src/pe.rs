//! Windows PE (Portable Executable) structures used for parsing and
//! manipulating PE files in `rivet-mini`.
//!
//! These definitions are intentionally `#[repr(C, packed)]` so they map to
//! the on-disk layout of PE headers. They are used when reading and writing
//! header fields from byte buffers.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageDosHeader {
  pub e_magic: u16,      // Magic number
  pub e_cblp: u16,       // Bytes on last page of file
  pub e_cp: u16,         // Pages in file
  pub e_crlc: u16,       // Relocations
  pub e_cparhdr: u16,    // Size of header in paragraphs
  pub e_minalloc: u16,   // Minimum extra paragraphs needed
  pub e_maxalloc: u16,   // Maximum extra paragraphs needed
  pub e_ss: u16,         // Initial (relative) SS value
  pub e_sp: u16,         // Initial SP value
  pub e_csum: u16,       // Checksum
  pub e_ip: u16,         // Initial IP value
  pub e_cs: u16,         // Initial (relative) CS value
  pub e_lfarlc: u16,     // File address of relocation table
  pub e_ovno: u16,       // Overlay number
  pub e_res: [u16; 4],   // Reserved words
  pub e_oemid: u16,      // OEM identifier (for e_oeminfo)
  pub e_oeminfo: u16,    // OEM information; e_oemid specific
  pub e_res2: [u16; 10], // Reserved words
  pub e_lfanew: i32,     // File address of new exe header
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageFileHeader {
  pub machine: u16,
  pub number_of_sections: u16,
  pub time_date_stamp: u32,
  pub pointer_to_symbol_table: u32,
  pub number_of_symbols: u32,
  pub size_of_optional_header: u16,
  pub characteristics: u16,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageOptionalHeader64 {
  pub magic: u16,
  pub major_linker_version: u8,
  pub minor_linker_version: u8,
  pub size_of_code: u32,
  pub size_of_initialized_data: u32,
  pub size_of_uninitialized_data: u32,
  pub address_of_entry_point: u32,
  pub base_of_code: u32,
  pub image_base: u64,
  pub section_alignment: u32,
  pub file_alignment: u32,
  pub major_operating_system_version: u16,
  pub minor_operating_system_version: u16,
  pub major_image_version: u16,
  pub minor_image_version: u16,
  pub major_subsystem_version: u16,
  pub minor_subsystem_version: u16,
  pub win32_version_value: u32,
  pub size_of_image: u32,
  pub size_of_headers: u32,
  pub check_sum: u32,
  pub subsystem: u16,
  pub dll_characteristics: u16,
  pub size_of_stack_reserve: u64,
  pub size_of_stack_commit: u64,
  pub size_of_heap_reserve: u64,
  pub size_of_heap_commit: u64,
  pub loader_flags: u32,
  pub number_of_rva_and_sizes: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageSectionHeader {
  pub name: [u8; 8],
  pub virtual_size: u32,
  pub virtual_address: u32,
  pub size_of_raw_data: u32,
  pub pointer_to_raw_data: u32,
  pub pointer_to_relocations: u32,
  pub pointer_to_linenumbers: u32,
  pub number_of_relocations: u16,
  pub number_of_linenumbers: u16,
  pub characteristics: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageDataDirectory {
  pub virtual_address: u32,
  pub size: u32,
}

pub const IMAGE_DOS_SIGNATURE: u16 = 0x5A4D; // MZ
pub const IMAGE_NT_SIGNATURE: u32 = 0x00004550; // PE\0\0

/// Minimum common Windows PE size this packer pads to (bytes).
///
/// Historically some extremely small PE stubs land around 268 bytes on
/// Windows; this constant documents that choice and centralizes the value.
pub const MIN_WINDOWS_PE_SIZE: usize = 268;

/// The canonical number of data directories in the PE Optional Header.
/// Most PE files use 16 directories (IMAGE_DIRECTORY_ENTRY_* entries).
#[allow(dead_code)]
pub const IMAGE_NUMBEROF_DIRECTORY_ENTRIES: usize = 16;

/// Optional header magic for PE32+ (64-bit) images.
#[allow(dead_code)]
pub const IMAGE_NT_OPTIONAL_HDR64_MAGIC: u16 = 0x20b;
