//! Windows PE (Portable Executable) structures used for parsing and
//! manipulating PE files in `rivet-mini`.
//!
//! These definitions are intentionally `#[repr(C, packed)]` so they map to
//! the on-disk layout of PE headers. They are used when reading and writing
//! header fields from byte buffers.
#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageDosHeader {
  /// Magic number
  pub e_magic: u16,
  /// Bytes on last page of file
  pub e_cblp: u16,
  /// Pages in file
  pub e_cp: u16,
  /// Relocations
  pub e_crlc: u16,
  /// Size of header in paragraphs
  pub e_cparhdr: u16,
  /// Minimum extra paragraphs needed
  pub e_minalloc: u16,
  /// Maximum extra paragraphs needed
  pub e_maxalloc: u16,
  /// Initial (relative) SS value
  pub e_ss: u16,
  /// Initial SP value
  pub e_sp: u16,
  /// Checksum
  pub e_csum: u16,
  /// Initial IP value
  pub e_ip: u16,
  /// Initial (relative) CS value
  pub e_cs: u16,
  /// File address of relocation table
  pub e_lfarlc: u16,
  /// Overlay number
  pub e_ovno: u16,
  /// Reserved words
  pub e_res: [u16; 4],
  /// OEM identifier (for e_oeminfo)
  pub e_oemid: u16,
  /// OEM information; e_oemid specific
  pub e_oeminfo: u16,
  /// Reserved words
  pub e_res2: [u16; 10],
  /// File address of new exe header
  pub e_lfanew: i32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageFileHeader {
  /// The architecture type of the computer.
  pub machine: u16,
  /// The number of sections.
  pub number_of_sections: u16,
  /// The low 32 bits of the time stamp of the image.
  pub time_date_stamp: u32,
  /// The offset of the symbol table, in bytes, or zero if no COFF symbol table exists.
  pub pointer_to_symbol_table: u32,
  /// The number of symbols in the symbol table.
  pub number_of_symbols: u32,
  /// The size of the optional header, in bytes.
  pub size_of_optional_header: u16,
  /// The characteristics of the image.
  pub characteristics: u16,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageOptionalHeader64 {
  /// The state of the image file.
  pub magic: u16,
  /// The major version number of the linker.
  pub major_linker_version: u8,
  /// The minor version number of the linker.
  pub minor_linker_version: u8,
  /// The size of the code section, in bytes, or the sum of all such sections if there are multiple code sections.
  pub size_of_code: u32,
  /// The size of the initialized data section, in bytes, or the sum of all such sections if there are multiple initialized data sections.
  pub size_of_initialized_data: u32,
  /// The size of the uninitialized data section, in bytes, or the sum of all such sections if there are multiple uninitialized data sections.
  pub size_of_uninitialized_data: u32,
  /// A pointer to the entry point function, relative to the image base address.
  pub address_of_entry_point: u32,
  /// A pointer to the beginning of the code section, relative to the image base.
  pub base_of_code: u32,
  /// The preferred address of the first byte of the image when it is loaded into memory.
  pub image_base: u64,
  /// The alignment of sections when loaded into memory, in bytes.
  pub section_alignment: u32,
  /// The alignment of the raw data of sections in the image file, in bytes.
  pub file_alignment: u32,
  /// The major version number of the required operating system.
  pub major_operating_system_version: u16,
  /// The minor version number of the required operating system.
  pub minor_operating_system_version: u16,
  /// The major version number of the image.
  pub major_image_version: u16,
  /// The minor version number of the image.
  pub minor_image_version: u16,
  /// The major version number of the subsystem.
  pub major_subsystem_version: u16,
  /// The minor version number of the subsystem.
  pub minor_subsystem_version: u16,
  /// This member is reserved and must be 0.
  pub win32_version_value: u32,
  /// The size of the image, in bytes, including all headers.
  pub size_of_image: u32,
  /// The combined size of the MS-DOS stub, the PE header, and the section headers, rounded to a multiple of the file alignment.
  pub size_of_headers: u32,
  /// The image file checksum.
  pub check_sum: u32,
  /// The subsystem required to run this image.
  pub subsystem: u16,
  /// The DLL characteristics of the image.
  pub dll_characteristics: u16,
  /// The number of bytes to reserve for the stack.
  pub size_of_stack_reserve: u64,
  /// The number of bytes to commit for the stack.
  pub size_of_stack_commit: u64,
  /// The number of bytes to reserve for the local heap.
  pub size_of_heap_reserve: u64,
  /// The number of bytes to commit for the local heap.
  pub size_of_heap_commit: u64,
  /// This member is obsolete.
  pub loader_flags: u32,
  /// The number of directory entries in the remainder of the optional header.
  pub number_of_rva_and_sizes: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageSectionHeader {
  /// An 8-byte, null-padded UTF-8 string.
  pub name: [u8; 8],
  /// The total size of the section when loaded into memory, in bytes.
  pub virtual_size: u32,
  /// The address of the first byte of the section when loaded into memory, relative to the image base.
  pub virtual_address: u32,
  /// The size of the initialized data on disk, in bytes.
  pub size_of_raw_data: u32,
  /// A file pointer to the first page of the section within the COFF file.
  pub pointer_to_raw_data: u32,
  /// A file pointer to the beginning of the relocation entries for the section.
  pub pointer_to_relocations: u32,
  /// A file pointer to the beginning of the line-number entries for the section.
  pub pointer_to_linenumbers: u32,
  /// The number of relocation entries for the section.
  pub number_of_relocations: u16,
  /// The number of line-number entries for the section.
  pub number_of_linenumbers: u16,
  /// The characteristics of the section.
  pub characteristics: u32,
}

#[repr(C, packed)]
#[derive(Debug, Copy, Clone)]
pub struct ImageDataDirectory {
  /// The relative virtual address of the table.
  pub virtual_address: u32,
  /// The size of the table, in bytes.
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
