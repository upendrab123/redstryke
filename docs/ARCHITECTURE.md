# Architecture — Autonomous AI Red Teamer

## Overview

Five-layer pipeline:

```
Target API
    ↓
[Layer 1] Attack Planner (Groq LLM)
    → Reads: target description, scan depth, memory context
    → Outputs: ordered list of AttackTask objects
    ↓
[Layer 2] Attack Executor (Garak + PyRIT in parallel)
    → Garak: automated probe suites (single-shot attacks)
    → PyRIT: multi-turn adversarial conversations
    → Outputs: stream of raw Finding objects
    ↓
[Layer 3] Evaluator (Groq LLM as judge)
    → Scores each finding: severity, regulatory mapping, reproduction steps
    → Outputs: EvaluationResult per finding
    ↓
[Layer 4] Memory Store (dual write)
    → SQLite: full structured audit trail (all attacks, all findings)
    → ChromaDB: embeddings of successful attacks (learning memory)
    ↓
[Layer 5] Report Generator
    → Groq writes executive summary
    → Jinja2 renders HTML report
    → WeasyPrint converts to PDF
    → PDF saved to data/reports/
```

## Learning Loop

The system improves across engagements via ChromaDB:

1. Successful attack → embed (type + prompt + target_desc) → store
2. New target → embed target_desc → query top-K similar past attacks
3. Planner receives retrieved attacks → adapts strategy

After ~10 engagements, the system has a domain-specific attack corpus.

## Groq Integration

All LLM calls go through Groq API (no local model required).
Three roles:
- **Planner**: temperature=0.7, generates creative attack strategies
- **Evaluator**: temperature=0.1, deterministic severity scoring
- **Reporter**: temperature=0.4, balanced executive summary writing

Rate limiting: 30 req/min (Groq free tier). Retry with exponential backoff.

## Key Design Decisions

- **No Ollama**: Groq API replaces local Ollama. Faster, no GPU needed.
- **Garak as subprocess**: Garak CLI is invoked via subprocess, results parsed from JSONL.
- **PyRIT as library**: PyRIT is used as a Python library directly.
- **Unified Finding schema**: Both Garak and PyRIT output is normalized to `Finding` dataclass.
- **SQLite over Postgres**: Simplicity. No server to manage. Sufficient for single-tenant use.
- **ChromaDB on disk**: Persists between runs. Mounted as Docker volume.