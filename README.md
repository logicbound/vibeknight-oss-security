# Vibe Knight Engine

Vibe Knight Engine is a Rust-based static application security testing (SAST) research project focused on vulnerability detection in JavaScript and TypeScript codebases.

The project is designed as a modular analysis pipeline:

- Language-specific frontends lower source code into a shared intermediate representation (IR)
- Rule modules run on IR and produce structured findings
- A CLI scans projects and exports findings in console or JSON format

## Research Objective

This repository supports practical research and portfolio work in:

- taint analysis for security detection
- language-agnostic rule design
- static vulnerability detection with explainable findings
- secure coding validation against realistic test fixtures

## Current Detection Scope

At the current stage, the engine includes:

- One built-in rule: SQL injection
- Taint-style source-to-sink analysis with sanitizer handling
- JavaScript/TypeScript frontend support (`.js`, `.jsx`, `.ts`, `.tsx`, `.mjs`, `.cjs`)

Supported patterns include common SQL execution sinks (for example `db.query`, `connection.query`, `execute`, ORM raw query APIs) and selected safe query-builder/sanitizer patterns.

## Repository Structure

This workspace is organized as a Rust multi-crate project:

- `vk-cli` - command-line interface
- `vk-core` - scanning pipeline, rule system, findings, analysis context
- `vk-ir` - shared intermediate representation and metadata
- `vk-lang-js` - JavaScript/TypeScript parser and IR lowering
- `macros` - shared internal macros/utilities

## Getting Started

### Prerequisites

- Rust toolchain (stable)
- Cargo

### Build

```bash
cargo build
```

### Run a Scan

Scan the current directory:

```bash
cargo run -p vk-cli -- scan --target .
```

Scan a specific path and exclude folders:

```bash
cargo run -p vk-cli -- scan --target ./example-project --exclude node_modules --exclude dist
```

Generate JSON output:

```bash
cargo run -p vk-cli -- scan --target ./example-project --output json
```

When `--output json` is used, the scanner writes `vibeknight-report.json` to the scanned directory (or file parent directory if scanning a single file).

## CLI Reference

```text
vk-cli scan [OPTIONS]

Options:
  -t, --target <TARGET>      Target directory (default: .)
  -o, --output <OUTPUT>      Output format: console | json (default: console)
  -e, --exclude [EXCLUDE]... Exclude folders or paths from scanning
```

## Development Notes

- Rules are registered in `vk-core/src/rules/mod.rs`
- Language frontends are registered in `vk-core/src/languages/mod.rs`
- Pattern providers map language-specific sources/sinks/sanitizers into core taint analysis
- Findings include severity, location, description, and optional data-flow/fix guidance

## Limitations (Current Stage)

- Detection coverage is currently focused on SQL injection
- Pattern matching and taint modeling are actively evolving
- False positives and false negatives are expected in research-stage analysis
- Only JavaScript/TypeScript frontend support is currently implemented

## Roadmap Direction

Planned expansion areas include:

- additional vulnerability classes (for example XSS, command injection, auth flaws)
- broader language frontend coverage
- improved interprocedural and framework-aware data-flow modeling
- benchmark-driven precision and recall evaluation

## Responsible Usage

This project is intended for defensive security research, code quality improvement, and educational use.  
Use outputs responsibly and comply with all applicable laws, policies, and authorization boundaries when testing real systems.

## Project Status

Active research prototype. APIs, rule behavior, and detection outputs may change as analysis quality improves.