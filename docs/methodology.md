# CSL-Meter Methodology

This document defines how CSL-Meter measures, what it publishes, and — just as
importantly — what it refuses to publish. Every rule here is enforced in code
(`csl_engine.py` / `app.py`); where this document and the code disagree, the
code wins and the document is the bug.

## 1. What is being measured

For each listed plan (a personal AI subscription or a pay-as-you-go API
offering), CSL-Meter runs a **probe battery**: a fixed set of real requests
sent to the provider's *official* endpoint with a key belonging to that plan.
From the responses it derives:

- **Consistency** — does the served model's response fingerprint stay stable,
  and does it agree across client framings ("harnesses")?
- **Substitution risk** — does the fingerprint match the *claimed* model's
  golden baseline, or does it sit closer to a different model?
- **Latency & metering honesty** — time-to-first-token, throughput, HTTP 429
  rate, and the ratio between reported token usage and what the plan's quota
  accounting implies.

The headline figure is the **CSL index** (0–100), computed from the net JSD
against the claimed baseline (weight 0.55), the split-half internal JSD
(0.25), and the token-usage ratio term (0.20), each term normalized against
fixed reference points in `compute_csl_index`.

## 2. The probe battery

One battery = **16 requests**, concurrency capped at 4:

| Part | Requests | Per-request token quota | Purpose |
|---|---|---|---|
| Distribution probes | 14 | 256 | Number-pick protocol; builds the observed response distribution |
| Tokenizer/cache audit probes | 2 | 16 | Usage-accounting and cache-behaviour telemetry |

Key properties:

- **Distribution fingerprinting.** Under the fixed number-pick protocol, each
  model family exhibits a characteristic distribution over response buckets.
  The observed distribution is compared with golden baselines by
  Jensen–Shannon divergence (JSD); similarity is reported as
  `(1 − JSD) × 100`. The report stores the observed distribution, the baseline
  distribution, and the full nearest-profile ranking, so every published
  number can be re-derived by a third party.
- **Harness de-biasing.** Client framings (raw API, Claude Code, Cursor,
  OpenCode) measurably skew the raw distribution. Before comparison, the
  observed distribution is corrected by a per-harness bias vector
  (`de_bias_harness_dist`) and renormalized; the split-half JSD between the
  battery's two halves is published alongside, so residual noise is visible
  rather than hidden.
- **Reasoning-aware extraction.** Reasoning models may spend the entire
  response budget on hidden reasoning and return an empty body. The extractor
  therefore looks, in order, at (1) the visible content with inline `<think>`
  blocks stripped, (2) the conclusion of the `reasoning_content` channel,
  (3) Anthropic-style `thinking` blocks. A probe counts as *extracted* only
  when a number is actually recovered.
- **Provider session requirements.** Where a provider's gateway requires a
  session header, one fresh session id is generated per battery and shared by
  all 16 requests; it is never stored.

## 3. Non-results: when no report may be filed

A battery that cannot support an honest conclusion produces **no report at
all** — never a degraded or fallback report. Three gates enforce this:

1. **Completion gate.** Fewer than 8 of the distribution probes completing
   successfully aborts the battery (`INSUFFICIENT_SAMPLES` / upstream error).
2. **Content gate.** Fewer than 8 *extracted* samples (numbers actually
   recovered, per §2) rejects the submission with
   `INSUFFICIENT_PROBE_CONTENT`, leaving stored reports and plan aggregates
   untouched. This separates *"the sample was insufficient to identify
   anything"* from *"the sample identified a different model"* — the two must
   never be conflated, because a reasoning model that exhausted its budget
   looks exactly like an empty distribution.
3. **Budget gate.** Real upstream usage is tallied as results arrive against
   a hard per-battery cap of **30,000 tokens** (`PROBE_TOKEN_BUDGET`).
   Crossing the cap aborts the battery with `PROBE_TOKEN_BUDGET_EXCEEDED`
   and no report.

Failed upstream authentication (401/403 from the provider) likewise files
nothing and reports `UPSTREAM_PROBE_FAILED` to the submitter.

## 4. Honest labeling (`data_origin`)

Every stored row carries a `data_origin`:

- `Simulated-Demo` — seeded/simulated baseline data, for display only.
- `Server-Verified` — produced by a real probe battery executed by the
  server against the official endpoint.

Rules, all enforced in code:

- Plan aggregates are computed **only** from Server-Verified reports. A plan
  flips to Server-Verified on its first real sample, and its demo numbers are
  replaced — never averaged with — real ones.
- Badges and pages derive their DEMO marker from `data_origin`, per plan and
  per report.
- The **site-wide** status is strict: it reports `verified-live` only when
  *every* listed plan holds at least one Server-Verified sample; otherwise it
  stays `demo-simulated`, however many plans are already verified.
- Nothing is ever relabeled after the fact: if a measurement is later found
  to be methodologically void, it is removed and aggregates are recomputed
  from the surviving reports.

## 5. Acceptance thresholds

Five thresholds govern what a deployment may claim. Thresholds **1, 2 and 5
are launch gates**; thresholds **3 and 4 are standing goals** whose measured
values are published as-is, whatever they currently are.

| # | Threshold | Status |
|---|---|---|
| 1 | Probe engine performs real outbound requests; simulated readings are impossible to mistake for verified ones (labeling per §4) | Launch gate |
| 2 | Credential hygiene: submitted API keys are never persisted (memory-only use; only a truncated SHA-256 dedup hash is stored), verified by raw database scan in the audit suite | Launch gate |
| 3 | Cross-harness identification: de-biased identification agrees across the four harness framings in ≥ 90% of live batteries | Standing goal — measured value published |
| 4 | Account safety: continuous probing of real personal accounts produces zero provider risk-control events (no bans, no forced re-verification attributable to probing) | Standing goal — measured value published |
| 5 | Availability & integrity under load: the audit suite's concurrent probe sessions complete with zero credential retention and zero cross-session data leakage | Launch gate |

## 6. Baseline calibration status

Golden baselines (`GOLDEN_BASELINES`) are the reference distributions each
claimed model is compared against. Their provenance is mixed: some derive
from verified first-party captures, others are not yet backed by a public,
re-derivable capture from the model's official endpoint.

Consequences, by design:

- A nearest-profile result is published as a *measurement against the current
  baselines*, with raw distributions attached — it is evidence, not a verdict.
- Public wording is fixed: a mismatch is stated as **"the observed
  distribution does not match the claimed model's baseline."** CSL-Meter does
  not publish "provider X substitutes models" as a conclusion until the
  relevant baseline is calibrated against a genuine first-party capture.
- Calibration captures are a standing public call for contributions: a raw
  probe transcript from a model's official endpoint, with enough metadata
  for anyone to re-run and re-derive the baseline. See `CONTRIBUTING.md`.

## 7. Credential and privacy rules

- Submitted API keys exist only in process memory for the duration of one
  battery. They are never written to the database, logs, or report payloads;
  the audit suite scans raw database bytes to prove it.
- Probe traffic goes only to whitelisted official provider endpoints; any
  other target is rejected before a request is made (SSRF whitelist).
- Probe submissions are gated by Cloudflare Turnstile with **fail-closed**
  semantics: if the verification secret is not configured, submissions are
  rejected rather than waved through.
