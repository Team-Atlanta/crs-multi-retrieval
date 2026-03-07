# crs-multi-retrieval

A [CRS](https://github.com/oss-crs) (Cyber Reasoning System) that uses a Multi Retrieval LangGraph agent to autonomously find and patch vulnerabilities in open-source projects.

Given proof-of-vulnerability (POV) inputs that crash a target binary, the agent analyzes the crashes, retrieves relevant code, generates patches, and verifies them — all autonomously.

## Project structure

```
patcher.py             # Patcher module: scan POVs → agent
pyproject.toml         # Package config (run_patcher entry point)
bin/
  compile_target       # Builder phase: compiles the target project
agents/
  template.py          # Agent template
crete/                 # Crete framework packages (ported from atlantis-crete)
  atoms/               # Action, Detection models
  agent/               # MultiRetrievalPatchAgent
  environment/         # OssFuzzEnvironment / libCRS environment
  evaluator/           # DefaultEvaluator
  analyzer/            # Crash analysis, JVM analyzers
  commons/             # Shared utilities
oss-crs/
  crs.yaml             # CRS metadata (supported languages, models, etc.)
  example-compose.yaml # Example crs-compose configuration
  base.Dockerfile      # Base image: Ubuntu + Python + ripgrep + LangChain
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

Copy `oss-crs/sample-litellm-config.yaml` and set your API credentials. The LiteLLM proxy routes agent API calls to the configured provider. All models in `required_llms` must be configured.

### 3. Run with oss-crs

```bash
crs-compose up -f crs-compose.yaml
```

## Configuration

| Environment variable | Default | Description |
|---|---|---|
| `CRS_AGENT` | `multi_retrieval` | Agent module name (maps to `agents/<name>.py`) |
| `MULTI_RETRIEVAL_MODEL` | `o4-mini` | Model used by the multi-retrieval agent |
| `AGENT_TIMEOUT` | `0` (no limit) | Agent timeout in seconds (0 = run until budget exhausted) |
| `BUILDER_MODULE` | `inc-builder-asan` | Builder sidecar module name (must match a `run_snapshot` entry in crs.yaml) |
