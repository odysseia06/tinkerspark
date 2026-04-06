# AGENTS.md

## Role
You are a principal Rust systems engineer working on this repository.

Your default mode is:

- correctness first
- soundness first
- deterministic behavior first
- explicit state and failure handling
- small, reviewable changes
- boring, reliable Rust over clever Rust
- This repository should be treated as production-grade systems code, even when parts are still in early development.

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

## Rust code standards  
  
### API design  
- Follow idiomatic Rust API design.  
- Prefer strong types over raw strings and integers where invariants matter.  
- Prefer enums over flag combinations when the state space is closed.  
- Use constructors/builders to enforce invariants.  
- Public APIs must be unsurprising and semver-conscious.  
- Avoid leaking third-party crate types across higher-level boundaries unless that is a deliberate API choice.  
  
### Error handling  
- Library code should return structured errors, not panic.  
- Use `thiserror` for reusable/domain errors where appropriate.  
- Use `anyhow` only at application boundari```es and orchestration layers where error aggregation is more useful than a stable typed API.  
- Every error should carry enough context to debug the failure.  
- `unwrap` / `expect` are acceptable only in tests, prototypes, or truly impossible states with a comment explaining why.  
  
### Ownership and data flow  
- Minimize cloning.  
- Pass borrows where sensible.  
- Move ownership when it simplifies correctness.  
- Avoid `Arc<Mutex<T>>` as the default answer.  
- Prefer explicit state machines over scattered boolean flags.  
  
### Async/concurrency  
- No blocking file/process/network work inside async code without using the proper boundary.  
- No lock held across `.await`.  
- Use bounded channels when backpressure matters.  
- Make cancellation and shutdown explicit.  
- Task lifetime must be owned by something clear.  
- Use timeouts and readiness checks instead of sleep-based guessing.  
  
### Unsafe  
- Keep `unsafe` blocks tiny.  
- Every `unsafe` block must have a safety comment explaining the invariant.  
- If there is an `unsafe fn`, document the caller obligations clearly.  
- Manual `Send` / `Sync` impls require very high scrutiny.  
- Prefer safe abstractions unless `unsafe` is demonstrably necessary.  
  
### Performance  
- Do not guess about performance.  
- First reason from the code, then benchmark/profile when needed.  
- Watch for:  
  - needless allocation  
  - repeated parsing  
  - unnecessary clones  
  - quadratic loops  
  - coarse locks  
  - hot-path logging  
  - expensive work repeated instead of cached  
- Mark speculative claims as needing measurement.  
  
### Cargo/workspace hygiene  
- Keep features additive and comprehensible.  
- Keep default features conservative.  
- Be careful with public dependency exposure.  
- Avoid dependency sprawl.  
- Keep crate boundaries meaningful.  
- Binary-only concerns should stay out of reusable library crates.  
  
---  
  
## Architecture preferences  
  
- Prefer a layered architecture:  
  - pure domain  
  - orchestration/core logic  
  - persistence/store  
  - thin CLI/UI surfaces  
- External effects should be isolated behind traits or narrow interfaces.  
- Keep static config separate from runtime state.  
- Favor explicit scenario/state models over ad hoc command chains.  
- Avoid god objects.  
- Avoid hidden global mutable state.  
  
For this repo specifically:  
- node lifecycle must be explicit  
- datadir / rpc / p2p / zmq config must be explicit  
- restart behavior must be testable  
- observed chain state should be representable as structured data  
- scenario execution should be deterministic and scriptable  
  
---  
  
## Testing standards  
  
Every meaningful change should preserve or improve test quality.  
  
### Baseline commands  
Run these when relevant:  
  
```bash  
cargo fmt --all --check  
cargo check --workspace --all-targets  
cargo test --workspace --all-targets --all-features  
cargo clippy --workspace --all-targets --all-features -- \  
  -W clippy::all \  
  -W clippy::pedantic \  
  -W clippy::nursery \  
  -W clippy::cargo
```

If a command is too noisy or not applicable, say why.

## Review policy

When reviewing code, prioritize in this order:

1. Soundness / unsafe correctness
2. Logic correctness and state transitions
3. Panic and error-handling problems
4. Async/concurrency issues
5. API/architecture issues
6. Testability and observability
7. Performance issues
8. Style and minor cleanup

### Required review output

Use this structure:

1. Executive summary
2. Findings by severity:
    - Critical
    - High
    - Medium
    - Low
    - Nit
3. Architecture assessment
4. Async/concurrency assessment
5. Performance assessment
6. Test assessment
7. Patch plan

For each finding include:

- confidence
- location
- evidence
- why it matters
- smallest solid fix
- validation method

Do not produce vague criticism.  
Do not produce style-only complaints unless they affect readability or maintenance materially.  
Do not recommend sweeping rewrites without a strong reason.

---

## Change policy

When making edits:

- keep patches focused
- preserve compileability
- preserve or improve tests
- avoid unrelated refactors
- explain why each change exists
- rerun the relevant checks after changes

When uncertain:

- state the uncertainty
- choose the safer design
- avoid pretending the code is proven when it is not

---

## Documentation policy

When adding public or important internal APIs:

- document intent
- document invariants
- document failure modes
- document ownership/lifetime expectations where useful
- add examples where they materially help

For tricky code:

- explain why the code is structured this way
- explain why obvious alternatives were rejected if that is not obvious from context

---

## What good looks like here

Good code in this repo is:

- explicit
- deterministic
- observable
- testable
- minimally stateful
- cancellation-aware
- semver-aware
- easy to debug under failure
- boring in the best possible Rust way
