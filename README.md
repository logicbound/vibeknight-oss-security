# vibeknight-engine

A **behavioural malware intelligence compiler** for npm packages.

Not a scanner. Not a linter. A deterministic pipeline that turns raw JavaScript packages into a structured execution model of what the code *can do at runtime* — ready for AI scoring, OSINT publication, and downstream signal reasoning.

---

## What it does

```
npm package (.tgz or registry name)
  → package_graph.json    (file tree + entry points + integrity hash)
  → ir_graph.json         (all behavioural IR nodes across all files)
  → behavior_graph.json   (execution chains from entry points to sinks)
  → finding.json          (signals + evidence — the product interface)
```

---

## Architecture

```
Source code  →  AST  →  IR  =  deterministic behavioural model of execution paths,
enriched with system interaction semantics, ready for scoring + AI reasoning + OSINT publication
```

Three strict layers:

| Layer | Crate | What it represents |
|---|---|---|
| **IR** | `vk-ir` | Facts — what *exists* in code (`ProcessExec`, `NetworkRequest`, `Eval`, …) |
| **Signals** | `vk-core` | Meaning — what it *means* (`PostinstallExecution`, `RemoteCodeExecution`, …) |
| **Graphs** | `vk-core` | Reality — execution paths, not feature lists |

`vk-ir` is the immutable schema contract. All crates depend on it. Nothing crosses stage boundaries except through `vk-ir` types.

---

## Pipeline stages

### Stage 1 — Ingestion (`vk-npm`)
- Accepts a local `.tgz` tarball or a registry package name (`pkg` / `pkg@1.2.3`)
- Downloads from the npm registry or reads from disk
- Extracts via `flate2` + `tar`
- Parses `package.json` — captures `scripts.preinstall`, `scripts.install`, `scripts.postinstall` as **execution triggers**, not metadata
- SHA-256 hashes the raw tarball for OSINT deduplication and reproducibility

### Stage 2+3 — AST → IR (`vk-lang-js`)
Two modules:

**`resolver`** — semantic binding tracker (this is what separates a semantic analyser from a regex scanner):
- `const cp = require('child_process')` → `cp → child_process`
- `const { exec } = require('child_process')` → `exec → child_process.exec`
- `cp['exec'](...)` bracket-access resolution
- `require(variable)` → `ObfuscatedFlow`

**`behavioral`** — two-pass OXC AST walker:
- Pass 1: collect all `require()` / `import` bindings into the resolver
- Pass 2: pattern match call expressions using resolved identities, emit `IrNode`s

Patterns detected:

| Resolved identity | IR node |
|---|---|
| `child_process.exec/spawn/execSync/…` | `ProcessExec` |
| `http.get`, `https.request`, `fetch`, `axios.*` | `NetworkRequest` |
| `fs.readFile/readFileSync/…` | `FileRead` |
| `fs.writeFile/appendFile/…` | `FileWrite` |
| `eval(…)` | `Eval` |
| `new Function(…)` | `FunctionConstructor` |
| `import(…)` | `DynamicImport` |
| `Buffer.from(x, 'base64')`, `atob()` | `EncodedString` |
| `require(variable)` | `ObfuscatedFlow` |

Arguments are captured only when statically determinable (string literal or substitution-free template). Dynamic args still emit the node — they're flagged, not ignored.

### Stage 4 — Flow linking + Signals (`vk-core`)
- **Call graph**: maps function declarations → call edges
- **Multi-path flow linker**: DFS from every `EntryPoint` node, annotated with `ExecutionEdge` semantics (`Direct`, `Conditional`, `Deferred`, `EventDriven`)
- **Signal derivation**: compositional pattern matching on IR facts — signals can be recalibrated without touching IR
- **Finding assembly**: produces the `finding.json` product interface

---

## CLI

```
# Analyse a local tarball
vk analyze --input ./malicious-pkg-1.0.0.tgz --output ./report/

# Fetch directly from the npm registry
vk analyze --input malicious-pkg --output ./report/
vk analyze --input malicious-pkg@1.0.0 --output ./report/
```

Output files written to `--output` directory:

| File | Contents |
|---|---|
| `package_graph.json` | File tree, entry points, integrity hash |
| `ir_graph.json` | All IR nodes across all JS/TS files |
| `behavior_graph.json` | Execution chains from entry points to sinks |
| `finding.json` | Signals, evidence, execution chains — the OSINT interface |

---

## Signals

Signals are derived *after* IR construction and are independent of the IR schema:

| Signal | Triggered by |
|---|---|
| `PostinstallExecution` | lifecycle script entry point present |
| `ShellChainExecution` | `ProcessExec` reachable from entry point |
| `RemotePayloadFetch` | `NetworkRequest` node present |
| `RemoteCodeExecution` | `NetworkRequest → Eval` in same execution chain |
| `DynamicCodeEval` | `Eval` or `FunctionConstructor` present |
| `EncodedPayloadDecode` | `EncodedString → Eval` in same chain |
| `ObfuscatedLoader` | `ObfuscatedFlow` node present |
| `FilesystemWrite` | `FileWrite` node present |
| `FilesystemRead` | `FileRead` node present |

`risk_score` is intentionally absent from the compiler output. Scoring belongs to the downstream AI/OSINT layer.

---

## Workspace layout

```
vibeknight-engine/
├── vk-ir/          IR schema — immutable fact types (IrNode, IrNodeKind, SourceLocation)
├── vk-npm/         Stage 1 — ingestion, extraction, hashing
├── vk-lang-js/     Stage 2+3 — OXC-based AST → IR (resolver + behavioral)
├── vk-core/        Stage 4 — call graph, flow linker, signals, finding
├── vk-cli/         CLI binary — dumb orchestration only
└── macros/         Utility macros
```

---

## Build

```sh
cargo build --release
cargo test
```

Requires Rust stable. No system npm installation needed for tarball analysis. Registry fetching requires network access.

---

## Design invariants

1. **IR is facts only** — `IrNode` never embeds signals, scores, or interpretations
2. **Signals are recalibratable** — derived in `vk-core` from IR, independent of the schema layer
3. **Same input = same output** — deterministic pipeline; artifact hashing enables OSINT dedup
4. **No LLMs in the parsing path** — AI belongs downstream; this tool produces the evidence
