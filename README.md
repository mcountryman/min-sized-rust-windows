# Minimum Binary Size Windows
An example of how small a rust binary can get on windows 10. Although I put a decent 
amount of effort into this I'm in no ways an expert and I have seen windows binaries get 
smaller on windows (https://github.com/pts/pts-tinype).

### Results
`1k` :sunglasses:

```powershell
❯ cargo build --release && (Get-Item ".\target\release\min-sized-rust-windows.exe").Length
    Finished release [optimized] target(s) in 0.02s
1024
```

### Strategies
I'm excluding basic strategies here such as enabling lto and setting `opt-level = 'z'`.

* [`no_std`](https://github.com/johnthagen/min-sized-rust#removing-libstd-with-no_std)
* [`no_main`](https://github.com/johnthagen/min-sized-rust#remove-corefmt-with-no_main-and-careful-usage-of-libstd)
* Merge `.rdata` and `.pdata` sections into `.text` section combined with `/ALIGN=512` linker flag.
    * Windows 10 section size appears to be locked at `1024`, so to avoid anything larger
    we merge everything into the `.text` section.
* `PEB` export walker
    * Piggy backing off of the previous findings we have a new issue.  When importing
    `kernel32.lib` we are stuck with an extra `1024`b `.idata` section.  Unfortunately
    `LINK.exe` really doesn't like it when you try to merge `.idata => .text`.  Since 
    `kernel32.dll` is accessible by default via the `PEB` I opted to obtain a reference to
    it and search the export directory for `GetStdHandle` and `WriteFile`.