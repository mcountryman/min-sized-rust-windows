# Minimum Binary Size Windows
The smallest hello world I could get on win10 x64 in rust. This isn't something meant to 
be used in production, more of a challenge.  I'm in no ways an expert and 
[I have seen windows binaries get smaller on windows](https://github.com/pts/pts-tinype). [2]
If you can go smaller let me know how you did it :grin:

### Results
`600b` :sunglasses:

```powershell
❯ cargo run --release
Hello World!

❯ cargo build --release && (Get-Item ".\target\release\min-sized-rust-windows.exe").Length
    Finished release [optimized] target(s) in 0.02s
600
```

### Strategies
I'm excluding basic strategies here such as enabling lto and setting `opt-level = 'z'`. [0]

* [`no_std`](https://github.com/johnthagen/min-sized-rust#removing-libstd-with-no_std)
* [`no_main`](https://github.com/johnthagen/min-sized-rust#remove-corefmt-with-no_main-and-careful-usage-of-libstd)
* Merge `.rdata` and `.pdata` sections into `.text` section linker flag. [1]
    * Using the LINK.exe [`/MERGE`](https://docs.microsoft.com/en-us/cpp/build/reference/merge-combine-sections?view=msvc-160)     
      flag found at the bottom of `main.rs`.
    * Section definitions add more junk to the final output, and I _believe_ they have a 
      min-size.  For this example we really don't care about readonly data (`.rdata`) or 
      exception handlers (`.pdata`) so we "merge" these empty sections into the `.text` 
      sections.
* No imports.
    * To avoid having an extra `.idata` section (more bytes and cannot be merged into 
      `.text` section using `LINK.exe`) we do the following.
      * Resolve stdout handle from `PEB`'s process parameters (thanks ChrisSD). [3][4]
      * Invoke `NtWriteFile`/`ZwWriteFile` using syscall `0x80`. [5][6]
        1. This is undocumented behaviour in windows, syscalls change overtime. [5]
        2. This will only work on windows 10, and was only tested on 10.0.19041 Build 19041.
    
### Future
* Using strategies shown in [[2]](https://github.com/pts/pts-tinype) we _could_ post process
  the exe and merge headers to get closer to the 600-500b mark although we start straying
  away from the goal of this project.
* Provided the call signature of `ZwWriteFile` I could use `build.rs` to make a script to
  dynamically resolve the syscall number from `ntdll` using something like [iced-x86](https://crates.io/crates/iced-x86).
* Go pure assembly (drop type definitions for PEB).
      
### References
0. https://github.com/johnthagen/min-sized-rust
1. www.catch22.net/tuts/win32/reducing-executable-size#use-the-right-linker-settings
2. https://github.com/pts/pts-tinype
3. https://news.ycombinator.com/item?id=25266892 (Thank you anonunivgrad & ChrisSD!)
4. https://processhacker.sourceforge.io/doc/struct___r_t_l___u_s_e_r___p_r_o_c_e_s_s___p_a_r_a_m_e_t_e_r_s.html
5. https://j00ru.vexillium.org/syscalls/nt/64/
6. https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntwritefile

### Credits
@Frago9876543210 - Brought binary size from `760b` -> `600b` :grin:
