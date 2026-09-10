# TRACE-API

Target-State Reasoning and Adaptive Control with Evidence for Autonomous API Penetration Testing.

## Overview

TRACE-API is an evidence-grounded agentic framework for autonomous penetration testing of HTTP/API targets. It couples deterministic security operators with LLM-guided reasoning through a persistent, API-specific state representation, so the agent reasons over an explicit model of the attack surface instead of reconstructing the interaction history at each step.

The framework combines a persistent API Asset Graph, vulnerability-knowledge grounding, hybrid deterministic--LLM reconnaissance, graph-conditioned attack planning and validation, and bounded fallback and replanning. Agent-side evidence judgments guide execution, while final exploitation outcomes are adjudicated independently from archived action--observation traces using target-specific criteria. This separation distinguishes apparent progress from objectively supported exploitation.

This repository contains the framework implementation. The benchmark dataset and the paper are maintained separately (see [Dataset](#dataset) and
[Citation](#citation)).

## Architecture

A TRACE-API assessment progresses through four coupled functions:

1. Target-state acquisition. Deterministic and LLM-guided reconnaissance build an explicit API Asset Graph of the observed attack surface (endpoints, methods, parameters, access conditions, and request relationships).
2. Knowledge-grounded reasoning. Observations are enriched with vulnerability context from a hybrid retrieval subsystem (dense plus keyword search) and an online CVE lookup service.
3. Adaptive planning and execution. Graph-conditioned attack plans are validated, executed, and revised, using distinct feedback for planning-time and execution-time failures within bounded replanning budgets.
4. Evidence-preserving assessment. Agent-side evidence judgments control flow, hile final outcome assessment remains separate from the attacking agent.

The corresponding source layout under `src/`:

| Module | Responsibility |
|--------|----------------|
| `graph/` | API Asset Graph: the persistent structured security state |
| `knowledge/` | Hybrid RAG (dense + BM25) and the OpenCVE lookup service |
| `agents/planning/` | Reconnaissance and graph-conditioned attack planning |
| `agents/exploiting/` | Evidence-aware exploitation and fallback |
| `orchestrator/` | Plan validation, replanning, and session control |
| `execution/` | Command execution on the host or in a Docker sandbox |
| `evaluation/` | Batch runs, metrics, and independent outcome assessment |
| `llm/` | Provider-agnostic LLM client (via LiteLLM) and prompts |
| `targets/` | Launch manifest and container lifecycle for dataset targets |

## Requirements

- Python 3.11 or later.
- Docker with Compose. The bundled CVE targets run as containerized environments, and batch and health-check commands launch them automatically.
- An API key for one LLM provider supported by LiteLLM (for example OpenAI, OpenRouter, DeepSeek, Anthropic, Google, or Mistral), or a local endpoint (Ollama, vLLM, LM Studio).

## Installation

```
git clone https://github.com/huuquyen2606/TRACE-API-Public.git
cd TRACE-API-Public
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Installation provides the `trace-api` command-line entry point.

## Configuration

The project uses a single configuration file. All settings, including secrets, live in `config/config.yaml`.

1. Copy the template:

   ```
   cp config/config.example.yaml config/config.yaml
   ```

2. Edit `config/config.yaml`:
   - Set `llm.provider`, `llm.model`, and `llm.api_key`.
   - For a local model, set `llm.api_base` and leave `llm.api_key` empty.
   - To enable CVE enrichment, set `cve_lookup.token` (online OpenCVE), or point `cve_lookup.base_url` at a self-hosted OpenCVE instance.

3. Verify the LLM connection:

   ```
   python scripts/check_llm_connection.py
   ```

## Usage

All commands accept `--config/-c` to select a configuration file (default `config/config.yaml`).

Build the retrieval knowledge base (ingests the background CVE corpus; target CVEs are excluded to prevent leakage):

```
trace-api knowledge ingest
trace-api knowledge stats
```

Run a single assessment against one target:

```
trace-api run http://localhost:8080 --cve-id CVE-2026-27483 --full
```

Inspect and operate on the bundled dataset:

```
trace-api targets                 # list detected CVE environments
trace-api healthcheck --all       # launch each target and check reachability
trace-api manifest generate       # (re)build the dataset launch manifest
```

Run the full pipeline over the dataset in batch:

```
trace-api batch --all                           # every CVE in the dataset
trace-api batch --wave 1                        # one sorted wave (sizes 9/9/9/8)
trace-api batch CVE-2026-27483,CVE-2024-24753
trace-api batch --all --fresh-knowledge         # reset the KB before the run
```

Review results:

```
trace-api sessions                # list saved sessions
trace-api session <session-id>    # show session details
trace-api report <session-id>     # (re)generate the Markdown report
trace-api aggregate <files...>    # combine batch metric files
```

Standalone utilities:

```
trace-api cve-lookup <product-name>
trace-api dir-enum http://localhost:8080
```

Sessions are written to `sessions/`, reports to `reports/`, and batch metrics to `evaluation_results/` (all configurable in `config/config.yaml`).

## Dataset

The benchmark dataset is not distributed in this repository. The dataset commands (`batch`, `healthcheck`, `targets`, `knowledge ingest`) expect a `dataset/` directory with:

- one folder per target CVE (`CVE-XXXX-XXXXX/`) holding a container environment that a Compose file or Dockerfile can launch;
- `manifest.yaml`, the launch manifest keyed by CVE (Compose path, ports, health path, timeouts); run `trace-api manifest generate` to create it;
- `HavePoC.json` and `NoPoC.json`, the background CVE corpus ingested into the retrieval knowledge base.

## Responsible Use

TRACE-API performs active exploitation and is intended for authorized security research only. Use it exclusively against systems you own or have explicit written permission to test, and prefer the isolated, containerized targets shipped with the benchmark. Because the agent acts autonomously, keep it on controlled networks and under human oversight. The authors accept no liability for misuse.

## Citation

This work is under peer review. If you use TRACE-API, please cite:

```bibtex
@unpublished{traceapi2026,
  title  = {{TRACE-API}: Target-State Reasoning and Adaptive Control with
            Evidence for Autonomous {API} Penetration Testing},
  author = {Phan Ban Nhat, Nam and Nguyen Huu, Quyen and Le Van, Quy and
            Nguyen Dang, Khoa and Pham, Van-Hau},
  note   = {Manuscript submitted for publication},
  year   = {2026}
}
```

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](LICENSE)
file for the full text.
