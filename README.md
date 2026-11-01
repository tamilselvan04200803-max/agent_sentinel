# AgentSentinel 🛡️
### Deterministic, Sandboxed, Evidence-First Automated Software Repair Engine

[![AgentSentinel CI](https://github.com/tamilselvan04200803-max/agent_sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/tamilselvan04200803-max/agent_sentinel/actions)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-3776AB?style=flat&logo=python&logoColor=white)](https://www.python.org/)
[![Type Checking: Mypy Strict](https://img.shields.io/badge/Mypy-Strict%20(53%20modules)-blue.svg)](https://mypy.readthedocs.io/)
[![Linter: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Tests: 1,342 Passed](https://img.shields.io/badge/Tests-1%2C342%20Passed%20%7C%200%20Failed-success.svg)](https://pytest.org/)
[![Sandbox: Docker Rootless](https://img.shields.io/badge/Sandbox-Docker%20Hardened-2496ED?style=flat&logo=docker&logoColor=white)](https://docs.docker.com/)
[![Provenance: DSSE PAE](https://img.shields.io/badge/Provenance-DSSE%20RFC%208785-critical.svg)](https://github.com/secure-systems-lab/dsse)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> **AgentSentinel is a zero-trust automated program repair (APR) and continuous integration guard engine.**  
> It proposes bounded repairs with an LLM, sanitizes Trojan/BiDi injections, validates patches against an AST security kernel, compiles differential mutants, isolates test runs inside hardened Linux Docker sandboxes, minimizes hunks via delta-debugging (`ddmin`), and locks verified repairs behind cryptographic DSSE PAE human approval gates.

---

## ⚡ The Problem: Why Coding Agents Break in Production

Most modern AI coding agents (and autonomous PR bots) operate on a naive loop: prompt an LLM, write code to disk, run tests, and merge if tests exit with `0`. In production, this causes catastrophic failure modes:

1. **Reward Hacking & Test Overfitting**: When an LLM fails to deduce the underlying algorithm, it cheats by constant-folding test assertions (`if input == 42: return "expected_result"`).
2. **Codeslop & Structural Bloat**: Agents hallucinate dozens of irrelevant helper functions, wrap failing logic in broad `except Exception: pass`, and swallow genuine runtime faults.
3. **Privilege Escalation & Secret Exfiltration**: Unsandboxed agents execute arbitrary malicious code on host runners, edit `.github/workflows`, or escape directories via symlink traversal.
4. **Public API Rot**: Patches quietly mutate positional parameters, change variadic `*args/**kwargs` semantics, or delete decorators, silently breaking downstream consumers.
5. **Amnesia & Zero Accountability**: Patches are merged without verifiable cryptographic provenance, making incident root-cause analysis impossible.

**AgentSentinel eliminates this attack surface at the compiler and runtime layers.**

---

## 🛡️ At-A-Glance Invariants & Guarantees

| Invariant | Guarantee | Technical Implementation |
|---|---|---|
| **Host Execution** | **0% Host Compromise** | Ephemeral rootless Docker containers, `--network=none`, `--cap-drop=ALL`, `/workspace:ro` host bind. |
| **Reward-Hacking Defense** | **Zero Assertion Tampering** | AST constant-folding literal matching catches hardcoded test values before container execution. |
| **Codeslop Minimization** | **1-Minimal Unified Diffs** | Delta-debugging (`ddmin`) drops extraneous hunks; cyclomatic growth capped at $\le +5$. |
| **API Preservation** | **Zero Backward Breakage** | Static AST signature comparison enforces public parameter contracts, defaults, and decorators. |
| **Cryptographic Provenance** | **Tamper-Evident Attestation** | RFC 8785 Canonical JSON (JCS) + in-toto DSSE Pre-Authentication Encoding (PAE) + HMAC-SHA256. |
| **CI Overhead** | **<500ms Static PR Audit** | Standalone `agentsentinel ci-gate` checks PR diffs with **0 LLM calls**, **0 Docker**, and **0 network**. |

---

## 🏛️ System Architecture

```text
                                 ┌───────────────────────────────┐
                                 │       FAILING REPO / CI       │
                                 └───────────────┬───────────────┘
                                                 │
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │    BASELINE REPRODUCTION      │
                                 │ (Must fail for declared bug)  │
                                 └───────────────┬───────────────┘
                                                 │
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │   AST FAULT LOCALIZATION      │
                                 │   Hop-0 and Hop-1 call frames │
                                 └───────────────┬───────────────┘
                                                 │
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │  SANITIZED PROMPT GENERATION  │
                                 │  BiDi / Trojan / Zero-Width   │
                                 └───────────────┬───────────────┘
                                                 │
                                                 ▼
                                 ┌───────────────────────────────┐
                                 │      LLM PATCH PROPOSAL       │
                                 │   Strict token/cost bounds    │
                                 └───────────────┬───────────────┘
                                                 │
          ┌──────────────────────────────────────┴──────────────────────────────────────┐
          │                                                                             │
          ▼                                                                             ▼
┌───────────────────────────────────┐                                 ┌───────────────────────────────────┐
│     TIER-1: SYNTACTIC POLICIES    │                                 │     TIER-2: AST SECURITY KERNEL   │
├───────────────────────────────────┤                                 ├───────────────────────────────────┤
│ • Strict path allowlists          │                                 │ • AST Constant-folding literals   │
│ • Protected paths (.git, CI)      │                                 │ • Semantic no-op dedup            │
│ • BiDi & non-ASCII id ban         │                                 │ • Cyclomatic growth limit (<= +5) │
│ • Unique-preimage hunk healing    │                                 │ • Exception-swallowing ban        │
│ • In-memory strict git apply      │                                 │ • Public API signature integrity  │
└─────────────────┬─────────────────┘                                 └─────────────────┬─────────────────┘
                  │                                                                     │
                  └──────────────────────────────────┬──────────────────────────────────┘
                                                     │
                                                     ▼
                                 ┌───────────────────────────────────────┐
                                 │       HARDENED LINUX SANDBOX          │
                                 │ • Ephemeral container per attempt     │
                                 │ • --network=none, --cap-drop=ALL      │
                                 │ • Read-only source bind (/workspace)  │
                                 └───────────────────┬───────────────────┘
                                                     │
                                                     ▼
                                 ┌───────────────────────────────────────┐
                                 │    DELTA-DEBUGGING & ADEQUACY PROBE   │
                                 │ • ddmin single-hunk / drop-one search │
                                 │ • Differential AST mutant synthesis   │
                                 │ • Bounded shadow tree adequacy probe  │
                                 └───────────────────┬───────────────────┘
                                                     │
                                                     ▼
                                 ┌───────────────────────────────────────┐
                                 │      CRYPTOGRAPHIC APPROVAL GATE      │
                                 │ SHA256(diff_hash + image + post_hash) │
                                 └───────────────────┬───────────────────┘
                                                     │
                                                     ▼
                                 ┌───────────────────────────────────────┐
                                 │       DSSE PAE EVIDENCE BUNDLE        │
                                 │  evidence.json, approved.patch,       │
                                 │  REPORT.md (RFC 8785 Canonical JSON)  │
                                 └───────────────────────────────────────┘
```

---

## 💻 CLI Command Center & Usage

AgentSentinel provides a modular CLI backed by durable SQLite checkpoints. Commands can be run across distinct machines, CI runners, and approval desks.

```
agentsentinel --help
  ├── ci-gate         # Zero-overhead, 50ms static PR diff auditor for CI/CD
  ├── run             # Orchestrates the sandboxed LLM repair state machine
  ├── status          # Inspects active run checkpoint and attempt telemetry
  ├── approve         # Cryptographically signs off on a verified repair
  ├── reject          # Rejects candidate repair with reason audit
  ├── export          # Emits RFC 8785 canonical evidence bundle (Approved runs only)
  ├── verify-bundle   # Offline cryptographic verification of DSSE evidence bundles
  └── benchmark       # Contamination-aware SWE-bench evaluation harness
```

### 1. Instant Static CI Gate (No Docker, No LLM)
Audit pull-request diffs directly in GitHub Actions in under 500ms:

```bash
agentsentinel ci-gate \
  --workspace . \
  --diff pr.patch \
  --json-out ci-audit.json \
  --markdown-out $GITHUB_STEP_SUMMARY
```
* **Exit 0**: Clean diff; no violations found.
* **Exit 1**: Policy violation (exception swallowing, CC growth $> +5$, hardcoded test literals, signature break).
* **Exit 2**: Unsafe path traversal, symlink escape, or malformed diff.

### 2. Autonomous Sandboxed Repair
Run the bounded repair state machine against a declared bug case:

```bash
agentsentinel run \
  --case-spec case.json \
  --db runs.db \
  --max-attempts 3 \
  --provider openai
```

When a patch passes verification, `agentsentinel run` exits with status `2` (`AWAITING_HUMAN_APPROVAL`) and prints the unforgeable cryptographic binding:

```text
STATUS: AWAITING_HUMAN_APPROVAL
RUN ID: run_7f9c31b8
DIFF HASH:        e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
IMAGE DIGEST:     sha256:4f8a31e8c1...
POST RESULT HASH: 9a2b5f1028e...
APPROVAL BINDING: sha256(diff_hash + image_digest + post_patch_hash)
```

### 3. Cryptographic Human Sign-Off
Approve or reject the verified repair:

```bash
# Approve with exact cryptographic binding
agentsentinel approve \
  --run-id run_7f9c31b8 \
  --approver-id alice@enterprise.io \
  --diff-hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 \
  --image-digest sha256:4f8a31e8c1... \
  --post-patch-result-hash 9a2b5f1028e... \
  --db runs.db

# Or reject with audit trail
agentsentinel reject \
  --run-id run_7f9c31b8 \
  --reviewer-id bob@enterprise.io \
  --reason "Requires additional regression assertions in test_auth.py" \
  --db runs.db
```

### 4. Export Evidence Bundle
Only cryptographically `APPROVED` runs can be exported:

```bash
agentsentinel export \
  --run-id run_7f9c31b8 \
  --output-dir ./evidence \
  --db runs.db
```

Generates a tamper-evident directory:
```text
evidence/run_7f9c31b8/
├── evidence.json   # RFC 8785 canonical JSON, CaseSpec, attempt ledger, bundle hash
├── approved.patch  # Exact approved unified diff (LF normalized)
└── REPORT.md       # Human-readable audit report with token costs and runtime metrics
```

### 5. Offline Provenance Verification
Verify an exported bundle without access to the database or Docker daemon:

```bash
agentsentinel verify-bundle \
  --bundle-dir ./evidence/run_7f9c31b8 \
  --require-keyed \
  --expected-policy-config-hash <trusted-sha256-hex>
```

---

## 🧬 Delta-Debugging (`ddmin`) & Mutation Probing

AI-generated patches often contain "accidental correctness"—modifying 5 files when only 1 line was needed, or making tests pass without actually fixing the vulnerability.

AgentSentinel counters this with two complementary stages (Milestone 13A):

```
Raw LLM Proposal (3 hunks, 42 lines)
  │
  ├── Hunk 1: Fixes off-by-one boundary
  ├── Hunk 2: Unneeded variable rename (codeslop)
  └── Hunk 3: Adds dead helper function (codeslop)
  │
  ▼
[ddmin Hunk Minimizer]
  ├── Test candidate [Hunk 1]: PASSES ALL TESTS ✅
  └── Test candidate [Hunk 2, 3]: FAILS ❌
  │
  ▼
Minimized Patch (1 hunk, 2 lines)
  │
  ▼
[Differential Mutation Probing]
  ├── Synthesizes 3 boundary mutants on Hunk 1 (e.g. `<` to `<=`)
  └── Runs mutants in isolated shadow containers
      ├── Mutant 1: KILLED (tests caught inversion)
      ├── Mutant 2: KILLED (tests caught boundary shift)
      └── Adequacy Score: 1.0 (High confidence)
```

Enable on state machine construction:
```python
RepairStateMachine(
    enable_ddmin_minimization=True,
    enable_mutation_probe=True,
    max_mutants=3,
)
```

---

## 🔐 The 18 Hardened Engineering Milestones

AgentSentinel was built across 18 verified milestones with zero tolerance for stubbed logic or mock implementations:

| Milestone | Subsystem | Engineering Invariants Enforced |
|---|---|---|
| **M0** | Core Domain Models | Frozen Pydantic models, deterministic exit codes, immutable types. |
| **M1** | Hardened Docker Sandbox | `--network=none`, `--cap-drop=ALL`, memory/CPU quotas, read-only host binds. |
| **M2** | Diff Parsing & Patch Policy | Strict `git apply`, symlink escape protection, path traversal defenses. |
| **M3** | LLM Client & Prompt Kernel | Token budgeting, model pricing, BiDi Trojan override and zero-width stripping. |
| **M4** | Repair State Machine | Deterministic finite state machine, atomic SQLite checkpoints, crash resilience. |
| **M5** | Contamination-Free Benchmark | Hardened admission gate; strictly isolates `reference_fix_patch` from LLM. |
| **M6** | CLI & Approval Exporter | Unkeyed & keyed cryptographic approval binding; deterministic evidence export. |
| **M7** | AST Fault Localizer | Deterministic Hop-0/Hop-1 call-stack traversal; container image digest pinning. |
| **M8** | Anti-Overfitting Kernel | AST constant-folding matches test literals; blocks reflection & eval. |
| **M9A** | Hunk Coordinate Healing | Unique-preimage coordinate rebasing heals LLM line drift without git apply errors. |
| **M9B** | Structural Bloat & Guards | Caps cyclomatic complexity growth ($\le +5$); bans `except: pass` exception swallowing. |
| **M10** | Differential AST Mutants | Synthesizes scoped logical/boundary mutants to probe test adequacy. |
| **M11** | Public API Contract Guard | Preserves public signatures, default values, variadics (`*args`), and descriptors. |
| **M12** | Typed Failure Taxonomy | 7 categorized failure classes with sanitized per-run retry diagnostics. |
| **M13A** | Live Post-Pass Minimization | Automated ddmin hunk minimization and live shadow-container mutation probing. |
| **M13B** | AST Skeletonizer | Line-accurate Python AST skeletonizer; bounds token budget for massive files. |
| **M13C** | Second-Order AST Defense | Symbolic constant folding (base64, hex, codecs, slicing); blocks obfuscated evasion. |
| **M14** | DSSE RFC 8785 Provenance | RFC 8785 Canonical JSON (JCS) with in-toto DSSE PAE and HMAC-SHA256 signing. |
| **M15** | Standalone CI Gate | Zero-overhead, $<500$ms static PR auditor for GitHub Actions & CI/CD. |
| **M16** | Causal Traceability | Undirected call-graph neighborhood localization & sandbox statement observation. |
| **M17** | Type-2 Alpha Clone Detector | Scope-aware AST subtree normalization; detects copy-pasted codeslop. |
| **M18** | SWEPatchTest Metrics | Standardized JVR/WDR/CAR metrics and Gate 5 policy-configuration digests. |

---

## 📁 Repository Structure

```text
src/agentsentinel/
├── cli/                 # Multi-command CLI (ci-gate, run, status, approve, export, verify)
├── domain/              # Immutable domain models, CaseSpec, ExitCode, EvidenceBundle
├── evaluation/          # Contamination-aware benchmark harness & SWEPatchTest JVR metrics
├── guards/              # AST security kernel (anti-overfitting, reflection, clone detection)
├── llm/                 # Deterministic LLM clients (OpenAI, Gemini, Mock) with token accounting
├── orchestrator/        # Fault localization, state machine, and SQLite checkpointing
├── policy/              # Diff parser, coordinate healing, and git apply validation
├── sandbox/             # Hardened rootless Linux Docker runner & workspace manager
└── verification/        # Minimization (ddmin), mutation probing, API compatibility, CI gate
```

---

## 🚀 Quick Start

### Prerequisites
* **Python**: 3.11, 3.12, or 3.13
* **Docker Desktop / Docker Engine** (Required for live containerized sandbox repair; optional for static `ci-gate`)

### Installation
```bash
# Clone the repository
git clone https://github.com/tamilselvan04200803-max/agent_sentinel.git
cd agent_sentinel

# Create and activate virtual environment
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.\.venv\Scripts\activate

# Install with development dependencies
pip install -e ".[dev]"

# Verify CLI
agentsentinel --help
```

### Run Full Verification Suite
```powershell
# 1. Run Ruff Linter
python -m ruff check src tests

# 2. Run Mypy Strict Type Checking across all 53 modules
python -m mypy --strict src

# 3. Run Automated Tests
python -m pytest tests/unit tests/adversarial --basetemp=.pytest_tmp -q
```

---

## 🔬 Benchmark Verification & Test Suite

AgentSentinel is verified by **1,343 automated tests**:
* **1,342 Passed**
* **0 Failed**
* **1 Skipped** (*Windows unprivileged symlink test; runs in privileged/Linux environments*)
* **16 Live Docker Integration Tests Passed** (rootless containers, network isolation, shadow workspaces)
* **`mypy --strict` Clean** across all 53 source modules.
* **Ruff Clean** with zero warnings.

```text
============================= test session starts =============================
platform win32 -- Python 3.13.7, pytest-8.4.2
collected 1343 items

tests/unit/test_*.py .................................................... [Pass]
tests/adversarial/test_*.py ............................................. [Pass]
tests/integration/test_docker_runner.py ................................ [Pass]

======================= 1342 passed, 1 skipped in 137.95s ======================
```

---

## ⚖️ Honest Limitations & Design Boundaries

1. **Benchmark Contamination**: Public historical bugs from popular open-source repositories may exist in LLM pre-training corpuses. AgentSentinel explicitly flags `is_public_historical_commit` rather than reporting inflated general repair capabilities.
2. **Deterministic Test Oracles**: AgentSentinel guarantees that repaired patches pass the declared test suite in isolation. If a test suite does not cover an edge case, no automated tool can infer unwritten business requirements. This is why **human approval remains a non-bypassable cryptographic gate**.
3. **Static Analysis Bounds**: The AST anti-overfitting kernel operates via symbolic constant folding and AST traversal without executing code. Dynamic runtime reflection constructed via unbounded network I/O cannot be fully resolved at compile time, which is why dynamic Docker sandboxing serves as the outer perimeter.

---


## 📄 License

AgentSentinel is licensed under the **MIT License**. See [LICENSE](LICENSE) for details.
