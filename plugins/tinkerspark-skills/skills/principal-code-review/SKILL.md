---
name: principal-code-review
description: Review code changes with a principal-engineer bar. Use when the user asks to review a PR, branch, diff, commit, merge candidate, or issue fix; when code was already written and needs a deep audit before merge or push; when an issue was solved and you need to verify the fix is correct; or when the user wants a structured findings report with severity, evidence, and a patch plan. Trigger on phrases like review this PR, review this issue fix, audit this diff, inspect this branch, check if this is safe to merge, request changes, or produce review findings.
---

# Principal Code Review

  

Review code like a principal engineer doing a real gate review, not a style pass.

  

Default priorities:

  

- correctness first

- safety and soundness first

- deterministic behavior first

- explicit state and failure handling

- small, reviewable changes

- boring, reliable code over clever code

  

If the repository contains `AGENTS.md`, `CLAUDE.md`, contribution docs, architecture docs, or language-specific standards, read them first and treat them as higher-priority project context. Use this skill as the review workflow and reporting standard on top of those local rules.

  

## When To Use

  

Use this skill when reviewing:

  

- a GitHub issue fix

- a PR or merge request

- a local branch before push

- a commit range or diff

- a hotfix before release

- code written by another agent or by yourself after implementation

  

Do not use this skill for casual brainstorming or for implementation tasks where the user has not asked for review.

  

## Review Posture

  

- Do not rubber-stamp.

- Do not invent problems that are not supported by the code or context.

- Do not ignore issue or PR context and review the diff in isolation.

- Do not produce vague criticism.

- Do not lead with style nits when there are correctness or safety risks.

- Do not recommend broad rewrites unless the current approach is unsound or structurally blocked.

- Do not describe code as safe, correct, or production-ready unless the evidence supports it.

  

If no material findings exist, say so explicitly and still call out residual risks or test gaps.

  

## Required Inputs

  

Gather the strongest context available before making findings:

  

- issue text, issue comments, and acceptance criteria when the review is issue-driven

- PR title, body, review comments, and CI status when the review is PR-driven

- changed files, diff, and commit history

- local project rules such as `AGENTS.md`, `CLAUDE.md`, `README`, design docs, and contribution guidance

- relevant tests, especially new or modified tests

  

If issue and implementation disagree, treat that mismatch as review material. Verify whether the code follows the real intent, not just the prose in the ticket.

  

## Review Workflow

  

### 1. Understand the Claimed Change

  

Before judging code, determine:

  

- what problem is being solved

- what behavior is expected to change

- what files or subsystems are affected

- what constraints or non-goals exist

  

Restate the change in plain language before moving to findings.

  

### 2. Read Tests First

  

Tests reveal intent and often expose missing coverage faster than implementation-first reading.

  

Check:

  

- whether the change added or updated tests

- whether tests actually prove the behavior claimed

- whether edge cases, error paths, and regressions are covered

- whether tests are deterministic and maintainable

  

If the change is meaningful and lacks adequate tests, that is usually at least a medium-severity finding, and higher when correctness risk is significant.

  

### 3. Read the Code With Context

  

Do not stop at the patch. Read surrounding code to understand:

  

- existing patterns and invariants

- upstream inputs and downstream consumers

- state transitions and lifecycle behavior

- failure handling and observability

- likely blast radius

  

For shared modules, boundary types, config, auth, persistence, concurrency, or process orchestration, widen the review scope until the effect of the change is clear.

  

### 4. Review in Priority Order

  

Always review in this order:

  

1. soundness, memory safety, and unsafe correctness where relevant

2. logic correctness and state transitions

3. panic, error handling, and failure visibility

4. async and concurrency behavior

5. API and architecture fit

6. security and trust boundaries

7. testability and observability

8. performance risks

9. readability and maintenance costs

10. style and nits

  

Do not bury a serious correctness or concurrency bug under minor cleanup comments.

  

### 5. Prefer the Smallest Solid Fix

  

For every finding, recommend the smallest fix that would materially resolve it.

  

Prefer:

  

- a focused code change

- reuse of existing methods, classes, helpers, and patterns

- a targeted test addition

- a narrow guard or validation check

  

Avoid:

  

- speculative abstractions

- "rewrite this whole module" advice without hard evidence

- adding dependencies to solve local review concerns when existing code can be extended

  

### 6. Validate the Review

  

Anchor findings in evidence:

  

- exact file and line or the narrowest precise location available

- behavior seen in the diff or surrounding code

- mismatch with issue/PR requirements

- mismatch with project rules

- mismatch with tests or missing tests

  

When uncertain, say so explicitly and downgrade confidence rather than overstating.

  

## Severity Model

  

Use these severities:

  

- `Critical`: unsafe, exploitable, data-loss, soundness, auth bypass, or merge-blocking correctness failure

- `High`: serious correctness, concurrency, API, or security risk likely to break production behavior

- `Medium`: meaningful maintainability, test, edge-case, or observability gap that should be fixed before merge in most cases

- `Low`: real but limited issue, cleanup with tangible maintenance value, or narrow non-blocking risk

- `Nit`: wording, naming, style, or polish that is optional unless it materially affects readability

  

If a finding is not backed by evidence, do not assign a severity.

  

## Language and Runtime Checks

  

Apply the repository's actual stack first. On top of that, watch for these classes of defects:

  

### General

  

- hidden failure paths

- unchecked inputs at boundaries

- state changes without invariant enforcement

- stale or misleading comments

- surprising public API changes

- weak or missing rollback and retry behavior

  

### Async and Concurrency

  

- locks held across await points

- blocking work inside async paths

- leaked tasks or unclear ownership of background work

- missing cancellation or shutdown handling

- race conditions on shared state

- unbounded queues where backpressure matters

  

### Rust-Specific

  

- unsound `unsafe`

- missing `// SAFETY:` justification

- incorrect `Send` or `Sync` assumptions

- `unwrap` or `expect` in library or reusable code without justification

- blocking in async runtimes

- sleep-based coordination where readiness or polling should exist

- semver-hostile public API exposure

  

### JS/TS/Python/Go and Similar

  

- swallowed exceptions or logged-but-ignored failures

- untyped or weakly typed boundaries where invariants matter

- unbounded retries or retry-without-classification

- injection or trust-boundary violations

- silent fallback behavior that hides broken state

  

## Issue and PR Alignment Checks

  

When reviewing an issue fix or PR tied to a ticket, always ask:

  

- Does the implementation solve the actual issue, not just the reported symptom?

- Is the issue valid on the current branch, or was it already fixed?

- Do the tests prove the fix and guard against recurrence?

- Does the code introduce unnecessary complexity relative to the issue scope?

- Is anything important missing from the acceptance criteria?

- Is the PR larger than necessary for the issue being solved?

  

If the issue is invalid, already fixed, or only partially addressed, say that clearly.

  

## Required Output

  

Always use this structure:

  

```markdown

1. Executive summary

  

2. Findings by severity

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
   - 
   - 
```

For each finding include:

  

- confidence

- location

- evidence

- why it matters

- smallest solid fix

- validation method

  

If a severity bucket has no findings, say `None`.

  

## Output Rules

  

- Executive summary should state the review verdict first: `block`, `request changes`, `approve with concerns`, or `approve`.

- Findings should be ordered by severity, then by likely impact.

- Use exact file paths and line references when possible.

- Distinguish confirmed defects from plausible risks.

- Keep architecture, concurrency, performance, and test sections substantive even when there are no major findings.

- Patch plan should be flat, concrete, and minimal. Do not turn it into a rewrite roadmap unless the change is fundamentally unsound.

  

## Approval Standard

  

Approve only when the change clearly improves the codebase and no remaining finding should reasonably block merge.

  

Request changes when the code is directionally fine but still has fixable issues that matter.

  

Block when the change has correctness, safety, concurrency, security, or verification failures that make merge unsafe.

  

## Review Checklist

  

Before finalizing the review, verify that you covered:

  

- issue or PR intent

- changed tests

- changed implementation

- nearby invariants and consumers

- error handling

- concurrency behavior

- security boundaries

- performance implications

- documentation and observability gaps

- smallest realistic patch plan

  

## Related Use

Pair this skill with issue-solving workflows when the code was just implemented and now needs a serious review pass before push or merge.
