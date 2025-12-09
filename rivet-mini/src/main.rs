mod pe;

use std::fs;
use std::process::Command;
use std::ptr;
use std::slice;

fn main() -> Result<(), Box<dyn std::error::Error>> {
  // Build the project first
  let status = Command::new("cargo")
    .args(["build", "--release", "--bin", "msrw-unpacked"])
    .status()?;

  if !status.success() {
    return Err(format!("Build failed with exit code: {:?}", status.code()).into());
  }

  let input_path = "./target/release/msrw-unpacked.exe";
  let output_path = "./target/release/msrw.exe";

  // println!("Reading inputs from {}", input_path);
  let buffer = fs::read(input_path)?;

  if buffer.len() < std::mem::size_of::<pe::ImageDosHeader>() {
    return Err("File too small".into());
  }

  // Parse Headers
  let dos_header =
    unsafe { ptr::read_unaligned(buffer.as_ptr() as *const pe::ImageDosHeader) };
  if dos_header.e_magic != pe::IMAGE_DOS_SIGNATURE {
    return Err("Invalid DOS signature".into());
  }

  let pe_header_offset = dos_header.e_lfanew as usize;
  if pe_header_offset + std::mem::size_of::<u32>() > buffer.len() {
    return Err("Invalid PE header offset".into());
  }

  let signature =
    unsafe { ptr::read_unaligned(buffer.as_ptr().add(pe_header_offset) as *const u32) };
  if signature != pe::IMAGE_NT_SIGNATURE {
    return Err("Invalid PE signature".into());
  }

  let file_header_offset = pe_header_offset + 4;
  let file_header = unsafe {
    ptr::read_unaligned(
      buffer.as_ptr().add(file_header_offset) as *const pe::ImageFileHeader
    )
  };

  let opt_header_offset = file_header_offset + std::mem::size_of::<pe::ImageFileHeader>();
  let opt_header = unsafe {
    ptr::read_unaligned(
      buffer.as_ptr().add(opt_header_offset) as *const pe::ImageOptionalHeader64
    )
  };

  let _image_base = opt_header.image_base;
  let section_alignment = opt_header.section_alignment;
  let file_alignment = opt_header.file_alignment;
  let original_entry_point = opt_header.address_of_entry_point;
  let original_base_of_code = opt_header.base_of_code;
  // println!("Original EntryPoint: 0x{:x}", original_entry_point);
  // println!("Original BaseOfCode: 0x{:x}", original_base_of_code);

  // println!("Original image base: 0x{:x}", image_base);
  // println!("Original section alignment: 0x{:x}", section_alignment);
  // println!("Original file alignment: 0x{:x}", file_alignment);
  let _size_of_image = opt_header.size_of_image;
  let _size_of_headers = opt_header.size_of_headers;
  // println!("Original SizeOfImage: 0x{:x}", size_of_image);
  // println!("Original SizeOfHeaders: 0x{:x}", size_of_headers);

  let sections_offset = opt_header_offset + file_header.size_of_optional_header as usize;
  let sections = unsafe {
    slice::from_raw_parts(
      buffer.as_ptr().add(sections_offset) as *const pe::ImageSectionHeader,
      file_header.number_of_sections as usize,
    )
  };

  let _orig_lfanew = dos_header.e_lfanew;
  // println!("Existing e_lfanew: {}", orig_lfanew);

  // --- PACKING STRATEGY ---

  let mut used_rva_count = 0;
  // We need to inspect data directories to find the last used one.
  // We can't easily access them via slice before we calculate offsets, but we need offsets to create buffer.
  // Access input data dirs.
  let input_data_dirs_offset =
    opt_header_offset + std::mem::size_of::<pe::ImageOptionalHeader64>();
  let input_num_rva = opt_header.number_of_rva_and_sizes as usize;
  let input_data_dirs = unsafe {
    slice::from_raw_parts(
      buffer.as_ptr().add(input_data_dirs_offset) as *const pe::ImageDataDirectory,
      input_num_rva,
    )
  };

  for (i, dir) in input_data_dirs.iter().enumerate() {
    let va = unsafe { ptr::read_unaligned(ptr::addr_of!(dir.virtual_address)) };
    let sz = unsafe { ptr::read_unaligned(ptr::addr_of!(dir.size)) };
    if va != 0 || sz != 0 {
      // println!("Used Data Dir {}: VA={:#x} Size={:#x}", i, va, sz);
      used_rva_count = i + 1;
    }
  }
  // println!(
  //   "Original RVA count: {}. Used: {}",
  //   input_num_rva, used_rva_count
  // );

  // Calculate NEW Header Size
  // Fixed Opt Header size
  let fixed_opt_header_size = std::mem::size_of::<pe::ImageOptionalHeader64>();
  let new_opt_header_size = fixed_opt_header_size
    + (used_rva_count * std::mem::size_of::<pe::ImageDataDirectory>());

  let new_pe_headers_size =
    4 + std::mem::size_of::<pe::ImageFileHeader>() + new_opt_header_size;

  let section_table_size = file_header.number_of_sections as usize
    * std::mem::size_of::<pe::ImageSectionHeader>();

  // Determine new layout
  let new_pe_offset = 4; // Overlap!
  let mut new_headers_top = new_pe_offset + new_pe_headers_size + section_table_size;

  // Align headers size to FileAlignment
  if file_alignment > 0 {
    let rem = new_headers_top % file_alignment as usize;
    if rem != 0 {
      new_headers_top += file_alignment as usize - rem;
    }
  }

  // println!("New headers size: {}", new_headers_top);

  let mut out_buffer = vec![0u8; new_headers_top];

  // 1. Copy DOS Header (first 64 bytes)
  unsafe {
    ptr::copy_nonoverlapping(buffer.as_ptr(), out_buffer.as_mut_ptr(), 64);
  }

  // 2. Update e_lfanew
  let out_dos_header =
    unsafe { &mut *(out_buffer.as_mut_ptr() as *mut pe::ImageDosHeader) };
  unsafe {
    ptr::write_unaligned(
      ptr::addr_of_mut!(out_dos_header.e_lfanew),
      new_pe_offset as i32,
    );
  }

  // 3. Copy PE Header (Signature + File + Opt + Data Dirs)
  // We handle copying carefully because sizes changed.

  // Signature
  unsafe {
    ptr::copy_nonoverlapping(
      buffer.as_ptr().add(pe_header_offset),
      out_buffer.as_mut_ptr().add(new_pe_offset),
      4,
    );
  }

  // File Header
  let out_file_header_offset = new_pe_offset + 4;
  unsafe {
    ptr::copy_nonoverlapping(
      buffer.as_ptr().add(file_header_offset),
      out_buffer.as_mut_ptr().add(out_file_header_offset),
      std::mem::size_of::<pe::ImageFileHeader>(),
    );
  }
  // Update SizeOfOptionalHeader in File Header
  unsafe {
    let out_fh = &mut *(out_buffer.as_mut_ptr().add(out_file_header_offset)
      as *mut pe::ImageFileHeader);
    ptr::write_unaligned(
      ptr::addr_of_mut!(out_fh.size_of_optional_header),
      new_opt_header_size as u16,
    );
  }

  // Optional Header (Fixed)
  let out_opt_header_offset =
    out_file_header_offset + std::mem::size_of::<pe::ImageFileHeader>();
  unsafe {
    ptr::copy_nonoverlapping(
      buffer.as_ptr().add(opt_header_offset),
      out_buffer.as_mut_ptr().add(out_opt_header_offset),
      fixed_opt_header_size,
    );
  }

  // Update NumberOfRvaAndSizes
  unsafe {
    let out_oh = &mut *(out_buffer.as_mut_ptr().add(out_opt_header_offset)
      as *mut pe::ImageOptionalHeader64);
    ptr::write_unaligned(
      ptr::addr_of_mut!(out_oh.number_of_rva_and_sizes),
      used_rva_count as u32,
    );
  }

  // Copy ONLY used Data Directories
  let data_dirs_offset = out_opt_header_offset + fixed_opt_header_size;
  unsafe {
    ptr::copy_nonoverlapping(
      buffer.as_ptr().add(input_data_dirs_offset), // Input Data Dirs
      out_buffer.as_mut_ptr().add(data_dirs_offset),
      used_rva_count * std::mem::size_of::<pe::ImageDataDirectory>(),
    );
  }

  // 4. Update Optional Header (SizeOfHeaders) later

  // 5. Append Sections and calculate patches
  struct SectionPatch {
    index: usize,
    old_va: u32,
    old_size: u32,
    new_va: u32,
    new_raw: u32,
    shift: u32,
    new_raw_size: u32,
  }

  let mut patches = Vec::new();
  let mut current_data_offset = new_headers_top;

  let mut max_raw_ptr = 0;
  for section in sections.iter() {
    let ptr =
      unsafe { ptr::read_unaligned(ptr::addr_of!(section.pointer_to_raw_data)) } as usize;
    let size =
      unsafe { ptr::read_unaligned(ptr::addr_of!(section.size_of_raw_data)) } as usize;
    if ptr + size > max_raw_ptr {
      max_raw_ptr = ptr + size;
    }
  }

  let overlay_size = if buffer.len() > max_raw_ptr {
    buffer.len() - max_raw_ptr
  } else {
    0
  };
  // println!("Found overlay data: {} bytes", overlay_size);

  for (i, section) in sections.iter().enumerate() {
    let mut original_raw_ptr =
      unsafe { ptr::read_unaligned(ptr::addr_of!(section.pointer_to_raw_data)) } as usize;
    let mut raw_size =
      unsafe { ptr::read_unaligned(ptr::addr_of!(section.size_of_raw_data)) } as usize;

    // If last section (by order in file or index?), append overlay
    // Usually last index is last in file.
    if i == sections.len() - 1 && overlay_size > 0 {
      raw_size += overlay_size;
      // println!(
      //   "Merging overlay into Section {}. New RawSize: 0x{:x}",
      //   i, raw_size
      // );
    }

    let mut original_va =
      unsafe { ptr::read_unaligned(ptr::addr_of!(section.virtual_address)) };
    let v_size_field =
      unsafe { ptr::read_unaligned(ptr::addr_of!(section.virtual_size)) };

    // println!(
    //   "Section {}: RawSize=0x{:x}, VirtualSize=0x{:x}, RawPtr=0x{:x}",
    //   i, raw_size, v_size_field, original_raw_ptr
    // );

    let virtual_size = if v_size_field > 0 {
      v_size_field
        + if i == sections.len() - 1 {
          overlay_size as u32
        } else {
          0
        }
    } else {
      raw_size as u32
    };

    // println!(
    //   "Section {}: RawSize=0x{:x}, VirtualSize=0x{:x}, RawPtr=0x{:x}",
    //   i, raw_size, v_size_field, original_raw_ptr
    // );
    // Print tail bytes of the section
    // Trim trailing zeros from raw data
    if raw_size > 0 {
      let start = original_raw_ptr;
      let limit = if start + raw_size > buffer.len() {
        buffer.len()
      } else {
        start + raw_size
      };
      let section_data = &buffer[start..limit];

      let mut new_len = section_data.len();
      while new_len > 0 && section_data[new_len - 1] == 0 {
        new_len -= 1;
      }

      // println!("Section {} trimmed: 0x{:x} -> 0x{:x}", i, raw_size, new_len);
      raw_size = new_len;
    }

    // Print EP relative to this section
    let check_va = original_va;
    if original_entry_point >= check_va {
      let offset = original_entry_point.wrapping_sub(check_va);
      // println!(
      //   "Section {} (VA 0x{:x}): EP Offset = 0x{:x}",
      //   i, check_va, offset
      // );

      // --- TRIM FRONT LOGIC ---
      // If EP is offset into section, the bytes before it are seemingly garbage.
      // We can trim them.
      if offset > 0 && offset < raw_size as u32 {
        // println!("Trimming 0x{:x} bytes from front of Section {}", offset, i);
        let trim_amt = offset as usize;
        raw_size -= trim_amt;
        original_raw_ptr += trim_amt;
        original_va += trim_amt as u32; // Important for patches
      }
    }

    if raw_size > 0 {
      let start = original_raw_ptr;
      let _end = start + raw_size;
    }
    if file_alignment > 0 {
      let rem = current_data_offset % file_alignment as usize;
      if rem != 0 {
        let padding = file_alignment as usize - rem;
        out_buffer.extend(std::iter::repeat_n(0, padding));
        current_data_offset += padding;
      }
    }

    let new_raw_ptr = current_data_offset;
    // Assuming Align=4, VA=Raw.
    let new_va = new_raw_ptr as u32;
    let shift = original_va.wrapping_sub(new_va);

    patches.push(SectionPatch {
      index: i,
      old_va: original_va,
      old_size: virtual_size,
      new_va,
      new_raw: new_raw_ptr as u32,
      shift,
      new_raw_size: raw_size as u32,
    });

    // Append data
    if raw_size > 0 {
      if original_raw_ptr + raw_size > buffer.len() {
        eprintln!("Warning: Section {} content truncated", i);
      } else {
        let data_slice = &buffer[original_raw_ptr..original_raw_ptr + raw_size];
        out_buffer.extend_from_slice(data_slice);
      }
    }

    current_data_offset += raw_size;
  }

  // println!("Packed size: {}", out_buffer.len());

  // 6. Apply Patches to Output Buffer
  // Re-acquire headers mutable
  let out_file_header_offset = new_pe_offset + 4;
  let out_opt_header_offset =
    out_file_header_offset + std::mem::size_of::<pe::ImageFileHeader>();

  let out_opt_header = unsafe {
    &mut *(out_buffer.as_mut_ptr().add(out_opt_header_offset)
      as *mut pe::ImageOptionalHeader64)
  };

  unsafe {
    ptr::write_unaligned(
      ptr::addr_of_mut!(out_opt_header.size_of_headers),
      new_headers_top as u32,
    );
  }

  // Calculate new SizeOfImage
  // It should be the end of the last section, aligned to SectionAlignment
  // We can track the max extent during the section loop.
  let mut max_extent = new_headers_top as u32;

  // Data Dirs
  let data_dirs_offset =
    out_opt_header_offset + std::mem::size_of::<pe::ImageOptionalHeader64>();
  // Note: we updated number_of_rva_and_sizes in buffer, but out_opt_header is a pointer to the buffer.
  // We can read it back or use used_rva_count.
  let num_rva = used_rva_count;
  let out_data_dirs = unsafe {
    slice::from_raw_parts_mut(
      out_buffer.as_mut_ptr().add(data_dirs_offset) as *mut pe::ImageDataDirectory,
      num_rva,
    )
  };

  // Section Headers now follow the Trimmed Optional Header
  let out_sections_offset =
    data_dirs_offset + (used_rva_count * std::mem::size_of::<pe::ImageDataDirectory>());
  let out_sections = unsafe {
    slice::from_raw_parts_mut(
      out_buffer.as_mut_ptr().add(out_sections_offset) as *mut pe::ImageSectionHeader,
      file_header.number_of_sections as usize,
    )
  };

  unsafe {
    ptr::copy_nonoverlapping(
      sections.as_ptr(),
      out_sections.as_mut_ptr(),
      file_header.number_of_sections as usize,
    );
  }

  // Now patch sections and globals
  for patch in &patches {
    let section = &mut out_sections[patch.index];
    unsafe {
      ptr::write_unaligned(
        ptr::addr_of_mut!(section.pointer_to_raw_data),
        patch.new_raw,
      );
      ptr::write_unaligned(ptr::addr_of_mut!(section.virtual_address), patch.new_va);
      ptr::write_unaligned(
        ptr::addr_of_mut!(section.size_of_raw_data),
        patch.new_raw_size,
      );
    }

    // println!(
    //   "Section {}: Shifted VA 0x{:x}->0x{:x}, Shift=0x{:x}",
    //   patch.index, patch.old_va, patch.new_va, patch.shift
    // );

    // Patch Global Entry Points
    if original_entry_point >= patch.old_va
      && original_entry_point < patch.old_va + patch.old_size
    {
      let new_ep = original_entry_point - patch.shift;
      unsafe {
        ptr::write_unaligned(
          ptr::addr_of_mut!(out_opt_header.address_of_entry_point),
          new_ep,
        );
      }
      // println!(
      //   "Patched EntryPoint: 0x{:x} -> 0x{:x}",
      //   original_entry_point, new_ep
      // );
    }

    if original_base_of_code >= patch.old_va
      && original_base_of_code < patch.old_va + patch.old_size
    {
      let new_boc = original_base_of_code - patch.shift;
      unsafe {
        ptr::write_unaligned(ptr::addr_of_mut!(out_opt_header.base_of_code), new_boc);
      }
      // println!(
      //   "Patched BaseOfCode: 0x{:x} -> 0x{:x}",
      //   original_base_of_code, new_boc
      // );
    }

    // Patch Data Dirs
    for dir in out_data_dirs.iter_mut() {
      let old = unsafe { ptr::read_unaligned(ptr::addr_of!(dir.virtual_address)) };
      if old >= patch.old_va && old < patch.old_va + patch.old_size {
        let new_rva = old - patch.shift;
        unsafe {
          ptr::write_unaligned(ptr::addr_of_mut!(dir.virtual_address), new_rva);
        }
        // println!("Patched DataDir {}: 0x{:x} -> 0x{:x}", k, old, new_rva);
      }
    }

    let extent = patch.new_va + patch.old_size; // Virtual extent
    if extent > max_extent {
      max_extent = extent;
    }
  }

  // Align max_extent
  if section_alignment > 0 {
    let rem = max_extent % section_alignment;
    if rem != 0 {
      max_extent += section_alignment - rem;
    }
  }

  // println!("New SizeOfImage: 0x{:x}", max_extent);
  unsafe {
    ptr::write_unaligned(ptr::addr_of_mut!(out_opt_header.size_of_image), max_extent);
  }

  // Write output
  // Pad to minimum Windows PE size (often 268 bytes) if needed
  while out_buffer.len() < 268 {
    out_buffer.push(0);
  }
  // println!("Final size with padding: {}", out_buffer.len());
  fs::write(output_path, &out_buffer)?;

  let reduction = 100.0 - (out_buffer.len() as f64 / buffer.len() as f64 * 100.0);
  println!(
    "Wrote {} bytes to {} ({:.1}% reduction)",
    out_buffer.len(),
    output_path,
    reduction
  );

  Ok(())
}
