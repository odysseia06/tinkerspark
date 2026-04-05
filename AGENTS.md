# AGENTS.md

## Mission
Build Tinkerspark as a safe desktop binary-analysis workstation for cryptographic files.

This repo is guided by three rules:
- raw bytes first
- structure second
- never modify the original file by default

## Non-Negotiables
- Desktop-first Rust application.
- Read-only open path.
- Patch overlay model for edits.
- New-file save semantics, not in-place overwrite.
- `ByteSource` remains the shared byte-access boundary.
- Analyzer plugins stay decoupled from the GUI and core byte engine.

## Delivery Standard
- Keep changes narrow and explain tradeoffs clearly.
- Prefer safe defaults and obvious boundaries.
- Mark placeholders honestly.
- Validate with formatting, compile checks, and tests when the workspace is available.
