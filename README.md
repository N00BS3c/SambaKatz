# SambaKatz

Stealthy LSASS dumper that exfiltrates memory over SMB — without touching disk.

SambaKatz uses Windows Transactional NTFS (TxF) to dump LSASS memory into a fake file that never actually gets written.

## How It Works

- Opens the LSASS process using its PID
- Starts a TxF transaction
- Dumps LSASS memory into a transacted file
- Reads the dump into memory
- Streams the dump over SMB to a remote share
- Rolls back the transaction — no local file ever saved

## Features

- No disk artifacts
- Built for in-memory loaders like Donut, Havoc
- SMB-only exfiltration (ideal for stealthy ops)
- Minimal dependencies (only WinAPI)

This project is inspired by:

- [Mimikatz](https://github.com/gentilkiwi/mimikatz) — by Benjamin Delpy (@gentilkiwi), the legendary LSASS and credential dumping tool.
- [Impacket](https://github.com/fortra/impacket) — for its excellent SMB tooling and examples.
