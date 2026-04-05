# Diff Test Fixtures

File pairs with known differences for testing the binary diff engine.

## Fixture Pairs

| Pair | Left | Right | What it tests |
|------|------|-------|---------------|
| identical | 256 B pattern | same | Zero changes reported |
| single-change | 256 B pattern | byte 0x40 = 0xFF | One ChangedRange at offset 0x40 |
| scattered | 256 B pattern | bytes at 0x10, 0x50, 0xA0 changed | Three separate ChangedRanges |
| block-change | 256 B pattern | 16 bytes at 0x30 = 0xFF | One contiguous 16-byte ChangedRange |
| right-longer | 256 B | 256 B + 32 B appended | Trailing length-difference range |
| left-longer | 256 B | 200 B (truncated) | Trailing length-difference range (other direction) |
| all-different | 128 B random (seed 42) | 128 B random (seed 42, different draw) | Single large ChangedRange covering entire file |
| empty | 0 B | 11 B "hello world" | Empty-vs-nonempty edge case |
| large | 64 KiB pattern | 8-byte changes at 1K, 8K, 32K, 60K | Multi-chunk diff, verifies chunked reading |
