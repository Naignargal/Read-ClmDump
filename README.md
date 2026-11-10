# Read-ClmDump
A Windows Minidump and kernel dump parser. Compatible in Constrained Language Mode

## What it reads
It reads Windows Minidump and Kernel dump files '.dmp' and '.mdmp', that have the PAGEDU64 and MDMP signature in the header. When parsing PAGEDU64 signed dumps limited information is provided but still usually enough to help (in my experience). There is a feature to pass the rest of the dump file to CDB.exe (Command Line Debugger) and grab more information. MDMP signed dumps have a lot more information and is well documented on its structure.

## Requirements
- Powershell 5.1 or 7
- Admin rights might be needed if the parser finds a file in a restriced folder.
- Optional: cdb.exe, there is a feature in the parser that can pass info to cdb.exe if you wish, you can always decline the pass off. Info on how to install the tool can be found [here](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools)

## Install
This is a Powershell Module so you will first need to determine where to install your Modules. Run '$env:PSMODULEPATH' to find the list of allowed paths to install modules. This will be different depending on if you have Powershell 5.1 or 7. Make a folder named ' Read-ClmDump ' then put Read-ClmDump.psm1 in it.
```
$env:PSMODULEPATH\Read-ClmDump\Read-ClmDump.psm1
```
Then:
```powershell
Import-Module Read-ClmDump
```
## Usage

Use exactly one of these switches:

| Switch | What it does |
|---|---|
| `-path <file>` | Parse a specific dump |
| `-scan` | List dumps in `C:\Windows\Minidump` and your profile, then pick one |
| `-scanforce` | Same, but also searches hidden folders and Windows Error Reporting folders (slower) |
| `-latest` | Parse the newest dump found by `-scan` |
| `-latestforce` | Parse the newest dump found by `-scanforce` |

```powershell
Read-ClmDump -path C:\Users\me\AppData\Local\CrashDumps\app.exe.1234.dmp
Read-ClmDump -scanforce
Read-ClmDump -latestforce -Verbose     # -Verbose shows each parsing step
```

`dumparser` is a built-in alias for `Read-ClmDump`.
## How it works

The module reads the dump's raw bytes with `Get-Content` and decodes the fields itself using the documented structures:

- **MDMP:** minidump header → stream directory → SystemInfo, MiscInfo, Exception, ModuleList and ThreadList streams.
- **PAGEDU64:** the fixed kernel dump header (`DUMP_HEADER64`).

Only the parts of the file that are needed get loaded, because byte reading in PowerShell with Constrained Language Mode is slow.

## Limitations

- **The stack scan is a heuristic, not a real stack trace.** It lists modules whose addresses appear on the crashing thread's stack. Most are return addresses, but some can be leftover values.
- **"Suspect" is a lead, not proof.** Hooking DLLs (security and privilege-management agents, overlays) appear on many stacks because they intercept calls.
- Register context (RIP/RSP) is only decoded for x64 MDMP dumps.
- PAGEDU64 parsing supports x64 only.
- Full-memory dumps (for example from Task Manager) may store thread stacks in a separate memory list that isn't read yet.
- PAGEDU64 does not identify the faulting driver without `cdb`.

## Known issues

- "Read past end of loaded bytes" on some MDMP dumps. To stay fast, the parser loads only the streams it needs plus an extra 1 MB. If a field it reads is stored further into the file, parsing stops with `Read past end of loaded bytes at offset 0x...`. Workaround: run with `-Verbose` to see how far it read, and raise the `1048576` margin in `Read-Mdmp`.
- Kernel (PAGEDU64) parsing stops early on unexpected values. If the dump isn't x64 or the dump type isn't recognized, the parser returns what it has read so far with an `Error` field instead of the full result.

## License

MIT

