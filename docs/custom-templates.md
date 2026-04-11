# Custom Format Templates

Tinkerspark can load user-defined binary format descriptions from TOML files.
Templates tell the structure pane how to label sequential fields in a file —
they are **structural guidance, not authoritative parsing**. If the file
doesn't match or data runs short, you'll get partial results with diagnostics.

## Template directory

Place `.toml` files in:

```
~/.tinkerspark/templates/
```

Templates are discovered on startup. Restart the app after adding or editing
templates.

## Requirements

Every template must have at least one match rule (`magic` or `extensions`) so
that it doesn't accidentally replace the generic analyzer for all files.

## TOML schema

```toml
[template]
name = "My Protocol"        # required, non-empty
endian = "big"               # "big" (default) or "little"

[match]
magic = [
    { offset = 0, bytes = "AB CD" },   # hex bytes, whitespace optional
]
extensions = ["proto", "bin"]           # case-insensitive

[[fields]]
name = "Magic Header"
type = "bytes"
size = 2

[[fields]]
name = "Version"
type = "u8"
known_values = { "1" = "v1.0", "2" = "v2.0" }

[[fields]]
name = "Payload Length"
type = "u32"

[[fields]]
name = "Payload"
type = "bytes"
size_from = "Payload Length"    # dynamic size from a previous integer field
```

## Field types

| Type    | Size    | Description                  |
|---------|---------|------------------------------|
| `u8`    | 1 byte  | Unsigned 8-bit integer       |
| `u16`   | 2 bytes | Unsigned 16-bit integer      |
| `u32`   | 4 bytes | Unsigned 32-bit integer      |
| `u64`   | 8 bytes | Unsigned 64-bit integer      |
| `i8`    | 1 byte  | Signed 8-bit integer         |
| `i16`   | 2 bytes | Signed 16-bit integer        |
| `i32`   | 4 bytes | Signed 32-bit integer        |
| `i64`   | 8 bytes | Signed 64-bit integer        |
| `bytes` | varies  | Raw byte sequence            |
| `utf8`  | varies  | UTF-8 text (lossy on error)  |

## Sizing for bytes/utf8

- **Fixed size:** `size = 4` reads exactly 4 bytes.
- **Dynamic size:** `size_from = "Length"` reads the number of bytes stored in
  a previous unsigned integer field named "Length".
- **Greedy:** omit both `size` and `size_from` to consume all remaining bytes.

## Known values

Any integer field can include a `known_values` table mapping the decimal string
to a label:

```toml
known_values = { "1" = "Request", "2" = "Response", "3" = "Heartbeat" }
```

When the parsed value matches a key, the structure pane shows both the raw
value and the label.

## Match precedence

- **Magic match** → `Medium` confidence (beats the generic analyzer).
- **Extension match** → `Low` confidence (ties with generic; template wins by
  registration order).
- **No match** → `None` (template is skipped for this file).

Templates are loaded in sorted filename order for deterministic behavior.

## Limitations

- Fields are strictly sequential from offset 0; there is no branching, loops,
  or offset-jumping.
- Templates cannot define nested structures or repeating record arrays.
- Only one template can win for a given file (highest confidence, then load
  order).
- Template reload requires restarting the application.
