# Contributing to Tinkerspark

Thank you for your interest. Bug reports, docs, new format analyzers, and core improvements are all welcome.

## Code of conduct

Be respectful and constructive.

## Project principles

`docs/architecture.md` explains the crate layout and the reasoning behind these
choices — read it before making structural changes.

## Getting started

### Prerequisites

- A recent **stable** Rust toolchain (install via [rustup](https://rustup.rs/)).
  The workspace uses the 2021 edition.
- A desktop environment — Tinkerspark is a GUI app built on
  [egui](https://github.com/emilk/egui)/eframe. On Linux you may need the usual
  native GUI development packages (e.g. `libgtk-3-dev` and the `libxcb` /
  `libxkbcommon` headers) for the file dialog and windowing backends.

### Before you submit

Run the baseline checks and make sure they pass:

```bash
cargo fmt --all
cargo check --workspace --all-targets
cargo test --workspace --all-targets
```

Clippy is encouraged, and the project aims for a clean pedantic bar:

```bash
cargo clippy --workspace --all-targets -- -W clippy::all -W clippy::pedantic
```

## License

Tinkerspark is licensed under the [MIT License](LICENSE). By contributing, you
agree that your contributions will be licensed under the same terms.
