#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Live T3 & T4 Evaluation CLI for Production Host (konspace.cc)
Usage on production server with real outbound internet:
  python3 scripts/run_live_t3_t4_eval.py --provider volcengine --plan coding-plan-lite --model kimi-k3 --key sk-...
Executes a real 16-request probe battery against the official provider endpoint and prints empirical T3/T4 telemetry.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from csl_engine import CSLDatabase


def main():
    parser = argparse.ArgumentParser(description="Run live T3/T4 probe evaluation with a real API key.")
    parser.add_argument("--provider", required=True, help="Whitelisted provider slug (e.g. openai, volcengine, kimi)")
    parser.add_argument("--plan", required=True, help="Plan slug (e.g. payg-official, coding-plan-lite)")
    parser.add_argument("--model", default="", help="Optional claimed model override")
    parser.add_argument("--harness", default="", help="Optional harness type (raw, claude-code, cursor, opencode)")
    parser.add_argument("--key", required=True, help="Real temporary API key (used in memory only, never saved)")
    parser.add_argument("--db", default="data/csl_meter.db", help="Path to SQLite DB")
    args = parser.parse_args()

    db = CSLDatabase(args.db)
    rep = db.record_probe_submission({
        "provider_slug": args.provider,
        "plan_slug": args.plan,
        "claimed_model": args.model,
        "harness_type": args.harness,
        "quota_window_stage": "window_early (<30%)",
        "api_key": args.key,
    })
    print(json.dumps({
        "uuid": rep["uuid"],
        "verification_mode": rep["verification_mode"],
        "data_origin": rep["data_origin"],
        "claimed_model": rep["claimed_model"],
        "nearest_profile_top1": rep["nearest_profile"],
        "csl_index": rep["csl_index"],
        "raw_jsd": rep["raw_jsd"],
        "net_jsd": rep["net_jsd"],
        "split_jsd": rep["split_jsd"],
        "tps": rep["tps"],
        "ttft_ms": rep["ttft_ms"],
        "rate_429_pct": rep["rate_429_pct"],
        "token_ratio": rep["token_ratio"],
        "cache_hit_pct": rep["cache_hit_pct"],
    }, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
