# Contributing to CSL-Meter

Contributions are welcome — especially the two kinds this project cannot
generate by itself: **baseline calibration captures** and **new provider
integrations**.

## 1. Baseline calibration captures (most wanted)

A golden baseline is only trustworthy if anyone can re-derive it from a
capture taken against the model's *official first-party endpoint*. To submit
one:

1. Use a first-party API key on the provider's official endpoint (not a
   reseller or relay — a relay capture calibrates the relay, not the model).
2. Run the standard battery against the claimed model:

   ```bash
   python3 scripts/run_live_t3_t4_eval.py \
     --provider <slug> --plan <plan> --model <claimed-model> --key <YOUR_KEY>
   ```

   Your key is used in memory only and never stored.
3. Open a PR (or issue) containing: the claimed model id, the provider
   endpoint host, the date, the raw observed distribution and ranking JSON
   from the report, and the harness framings used. Do **not** include your
   API key, account identifiers, or billing details.
4. A maintainer re-derives the baseline from your capture and records the
   provenance (endpoint, date, method version) next to the baseline entry.

Baselines without re-derivable provenance are marked as uncalibrated in
`docs/methodology.md` §6, and readings against them are worded accordingly.

## 2. New provider integrations

A provider entry needs: the official endpoint base URL (whitelist — no
third-party relays), protocol flavour (OpenAI-compatible or Anthropic), the
plan's claimed model id, and any gateway quirks (e.g. a required session
header, declared in the provider entry so one id is issued per battery).
Add the entry, add a plan seed, and extend the tests so the whitelist and
probe path are covered.

## 3. Code contributions

- Pure Python 3 standard library — please do not add runtime dependencies.
- Fork, branch, PR. Describe the measurement impact of your change: if it
  touches extraction, scoring, labeling, or aggregation, say what happens to
  previously published readings.
- **Tests are the contract.** Before submitting, run the full suite and keep
  it green:

  ```bash
  python3 -m unittest discover -s tests
  python3 scripts/security_audit.py
  ```

  Changes to probe behaviour should come with a test that would have caught
  the old behaviour (the suite's stub upstreams simulate reasoning-exhausted
  models, fake keys, and hostile token-usage reports — reuse them).
- Honesty rules are not negotiable in review: no simulated data may ever be
  labeled verified, insufficient samples must remain non-results, and
  credentials must never touch disk. PRs that weaken a labeling or retention
  rule will be asked to re-read `docs/methodology.md` instead of merged.

## 4. Reporting a wrong reading

If a published reading looks wrong, open an issue with the report id and
what you measured yourself. Wrong readings traced to a methodology defect are
removed and aggregates recomputed, with the removal noted — silently editing
a number is the one thing this project never does.
