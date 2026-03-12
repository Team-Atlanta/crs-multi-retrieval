# crs-multi-retrieval

A [CRS](https://github.com/oss-crs) (Cyber Reasoning System) that uses the MultiRetrieval agent to autonomously find and patch vulnerabilities in open-source projects.

MultiRetrieval follows a two-step workflow: it first analyzes the crash to gather relevant code context, then iteratively generates and refines patches. It uses multiple code-query mechanisms to expand context as needed during patch synthesis, helping the system improve patches steadily across iterations.

## How it works

```
┌─────────────────────────────────────────────────────────────────────┐
│ patcher.py (orchestrator)                                           │
│                                                                     │
│  1. Fetch POVs, optional ref diff, and source                       │
│     crs.fetch(POV / DIFF)                                           │
│     crs.download(src)                                               │
│         │                                                           │
│         ▼                                                           │
│  2. Reproduce crashes on base build                                 │
│     libCRS run-pov (build-id: base)                                 │
│     → crash_log_*.txt                                               │
│         │                                                           │
│         ▼                                                           │
│  3. Launch Multi Retrieval agent with POV blobs + crash context     │
└─────────┬───────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────────────────────────────────────────────────┐
│ Multi Retrieval agent (crete / LangGraph)                           │
│                                                                     │
│  ┌──────────────┐   ┌──────────────┐   ┌─────────────────────────┐  │
│  │   Analyze    │──▶│   Retrieve   │──▶│     Patch / Evaluate    │  │
│  │              │   │              │   │                         │  │
│  │ Crash logs   │   │ ripgrep /    │   │ apply-patch-build ────▶ │  │
│  │ POV blobs    │   │ file / AST   │   │ run-pov (all POVs) ───▶ │  │
│  │ ref diff     │   │ retrieval    │   │ run-test ─────────────▶ │  │
│  └──────────────┘   └──────────────┘   └──────────┬──────────────┘  │
│                                                   │                 │
│                                      best diff ◀──┘                 │
│                                                   │                 │
│                              Write .diff to /patches/               │
└─────────────────────────────────────────────────────────────────────┘
          │
          ▼
┌─────────────────────────┐
│ Submission daemon        │
│ watches /patches/ ──────▶ oss-crs framework (auto-submit)
└─────────────────────────┘
```

1. **`run_patcher`** fetches POVs, the target source tree, and an optional reference diff for delta mode, then reproduces crashes on the unpatched build via the builder sidecar.
2. All POVs are treated as variants of the same vulnerability and passed to the **Multi Retrieval agent** in one session.
3. The agent builds a detection context from POV blobs, retrieves relevant files and code ranges, generates candidate patches, and evaluates them through **libCRS** (`apply-patch-build`, `run-pov`, `run-test`) using the builder sidecar.
4. The best verified `.diff` is written to `/patches/`, where a daemon auto-submits it to the oss-crs framework.

The agent is language-agnostic at the orchestration layer and supports `c`, `c++`, and `jvm` targets declared in `oss-crs/crs.yaml`.

## Project structure

```
patcher.py             # Patcher module: scan POVs → agent
pyproject.toml         # Package config (run_patcher entry point)
bin/
  compile_target       # Builder phase: compiles the target project
agents/
  multi_retrieval.py   # Multi-retrieval agent (default)
  template.py          # Stub for creating new agents
crete/
  agent/               # MultiRetrievalPatchAgent and context
  analyzer/            # Crash analysis helpers, JVM analyzers
  atoms/               # Detection and action models
  commons/             # Shared utilities
  environment/         # libCRS-backed execution environment
  evaluator/           # Patch evaluation logic
  patcher/             # LLM-driven patch generation workflow
  retriever/           # ripgrep / file / AST retrieval graph
  state/               # Workflow state models
  workflow/            # System-guided patch workflow
oss-crs/
  crs.yaml             # CRS metadata (supported languages, models, etc.)
  example-compose.yaml # Example crs-compose configuration
  base.Dockerfile      # Base image: Ubuntu + Python + retrieval deps
  builder.Dockerfile   # Build phase image
  patcher.Dockerfile   # Run phase image
  docker-bake.hcl      # Docker Bake config for the base image
  sample-litellm-config.yaml  # LiteLLM proxy config template
```

## Prerequisites

- **[oss-crs](https://github.com/oss-crs/oss-crs)** — the CRS framework (`crs-compose` CLI)

Builder sidecars for incremental builds are declared in `oss-crs/crs.yaml` (`snapshot: true` / `run_snapshot: true`) and handled automatically by the framework — no separate builder setup is needed.

## Quick start

### 1. Configure `crs-compose.yaml`

Copy `oss-crs/example-compose.yaml` and update the paths:

```yaml
crs-multi-retrieval:
  source:
    local_path: /path/to/crs-multi-retrieval
  cpuset: "2-7"
  memory: "16G"
  llm_budget: 10
  additional_env:
    CRS_AGENT: multi_retrieval
    MULTI_RETRIEVAL_MODEL: o4-mini

llm_config:
  litellm_config: /path/to/sample-litellm-config.yaml
```

### 2. Configure LiteLLM

Copy `oss-crs/sample-litellm-config.yaml` and set your API credentials. The LiteLLM proxy routes the agent's model calls to the configured provider. If you keep the defaults, configure both `o4-mini` and `gemini-2.5-pro`.

### 3. Run with oss-crs

```bash
crs-compose up -f crs-compose.yaml
```

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `CRS_AGENT` | `multi_retrieval` | Agent module name (maps to `agents/<name>.py`) |
| `MULTI_RETRIEVAL_MODEL` | `o4-mini` | Primary model used by the multi-retrieval agent |
| `MULTI_RETRIEVAL_BACKUP_MODEL` | `gemini-2.5-pro` | Backup model used when the workflow falls back to a second LLM |
| `BUILDER_MODULE` | `inc-builder-asan` | Builder sidecar module name (must match a `run_snapshot` entry in `crs.yaml`) |
| `SUBMISSION_FLUSH_WAIT_SECS` | `12` | Delay before exit so the patch submission watcher can flush |

Available models in the sample LiteLLM config:
- `o4-mini`
- `gemini-2.5-pro`

## Runtime behavior

- **Execution**: the patcher runs non-interactively inside the CRS container
- **POV handling**: all fetched POV files are batched into a single detection and treated as variants of the same bug
- **Delta mode**: if `/work/diffs/ref.diff` exists, the agent includes it as reference context
- **Build / test backend**: all validation runs through the builder sidecar via libCRS

Debug artifacts:
- Shared work directory: `/work`
- Per-run agent outputs: `/work/agent/`
- Fetched POVs: `/work/povs/`
- Fetched delta diff: `/work/diffs/ref.diff`

## Patch validity

A patch is submitted only when it meets all criteria:

1. **Builds** — compiles successfully through `apply-patch-build`
2. **POVs don't crash** — all POV variants pass
3. **Tests pass** — project test suite passes when available
4. **Semantically correct** — the selected diff is the best validated candidate produced by the workflow

Submission is final once a `.diff` is written to `/patches/` and picked up by the watcher. Submitted patches cannot be edited or resubmitted, so the agent must finish validation before writing the patch file.
