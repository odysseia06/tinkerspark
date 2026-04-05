# Tinkerspark

A desktop workstation for inspecting, diffing, and patching binary files.

Built with Rust and [egui](https://github.com/emilk/egui).

## Features

- **Hex viewer** — virtual-scrolling hex grid with ASCII preview, keyboard nav, search, selection metadata
- **Patch layer** — edit bytes as same-length overlays with undo/redo; save as a new file, never overwrite
- **Binary diff** — side-by-side comparison, synchronized scroll, per-change merge, merged-region highlighting
- **OpenPGP analyzer** — auto-detects armored/binary OpenPGP, parses packets with Sequoia, maps structure to byte ranges
- **Tabbed workspace** — multiple files and diffs open as tabs, session restore across restart

## Build

```
cargo build --release
```

## Run

```
cargo run -p tinkerspark-app-desktop
```

Or run the built binary directly from `target/release/`.

## Test

```
cargo test
```

## License

[MIT](LICENSE)
