# AgentShield Detection Benchmark

This benchmark evaluates AgentShield's detection accuracy across
multiple attack categories and benign samples.

## Structure
- `malicious/` — 24 attack samples covering all rule categories
- `benign/` — 20 safe samples including edge cases (security docs, legitimate tools with eval/HTTP/subprocess)
- `run.ts` — Benchmark runner script
- `results.md` — Latest benchmark results with gap analysis

## Run

```bash
npx tsx benchmark/run.ts
```

## Metrics
- **Recall** = true positives / (true positives + false negatives)
- **FPR** = false positives / (false positives + true negatives)
- **Precision** = true positives / (true positives + false positives)
- **F1** = 2 × precision × recall / (precision + recall)

## Latest Results (V2)

| Metric | Value |
|--------|-------|
| Recall | 91.7% |
| Precision | 91.7% |
| F1 Score | 91.7% |
| FPR | 10.0% |
| Accuracy | 90.9% |

See `results.md` for full analysis, rule coverage, gap analysis, and snyk comparison.
