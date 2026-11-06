#!/usr/bin/env python3
"""
scripts/calibrate_golden_baselines.py

Executable Calibration Tool for CSL-Meter Golden Baselines:
- Strictly restricts calibration to the 10 official first-party direct API endpoints
  (explicitly rejecting opencode, commandcode, kilo, cursor, kiro, copilot harnesses/aggregators)
- Enforces strict model-to-provider pairing across all 16 GOLDEN_BASELINES models
  (including official DeepSeek endpoint https://api.deepseek.com/chat/completions)
- Reads API key exclusively from environment variables (default: CSL_CALIBRATION_API_KEY)
  so secrets never appear in shell history or process argv
- Enforces sample count N as a multiple of len(PROBE_PROMPTS_POOL) (14), with N >= 210
  for baseline mode and minimum valid extraction threshold >= ceil(N * 8 / 14)
- Persists full per-probe records (prompt_index, status_code, elapsed_ms, extracted_token,
  usage, had_reasoning) and run_conditions (temperature=1.0, max_tokens=256, top_p_sent=False,
  prompt_pool_sha256, engine_commit_sha, mode) for complete audit reproducibility
"""

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# Add repository root to sys.path so csl_engine can be imported cleanly
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import csl_engine
from csl_engine import (
    ALLOWED_PROVIDERS,
    GOLDEN_BASELINES,
    PROBE_BUCKETS,
    PROBE_PROMPTS_POOL,
    _call_single_upstream_probe,
    compute_jsd,
    extract_number_from_reasoning_or_content,
    normalize_dist,
)

# Strictly whitelisted official first-party direct endpoints and their paired models.
# Aggregator and IDE harness slugs (opencode, commandcode, kilo, cursor, kiro, copilot)
# are explicitly excluded from baseline calibration.
EXCLUDED_NON_DIRECT_PROVIDERS = frozenset(
    {"opencode", "commandcode", "kilo", "cursor", "kiro", "copilot"}
)

OFFICIAL_DIRECT_PROVIDERS = {
    "openai": {
        "name": "OpenAI Official Direct",
        "family": "OpenAI",
        "protocol": "openai",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "models": ("gpt-5.6-sol", "gpt-6-astra", "gpt-5.6-luna"),
    },
    "anthropic": {
        "name": "Anthropic Official Direct",
        "family": "Anthropic",
        "protocol": "anthropic",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "models": ("claude-opus-5.5", "claude-sonnet-5", "claude-haiku-4.5"),
    },
    "xai": {
        "name": "xAI (Grok Official Direct)",
        "family": "xAI",
        "protocol": "openai",
        "endpoint": "https://api.x.ai/v1/chat/completions",
        "models": ("grok-4.7",),
    },
    "kimi": {
        "name": "Moonshot Kimi Official Direct",
        "family": "Moonshot",
        "protocol": "openai",
        "endpoint": "https://api.moonshot.cn/v1/chat/completions",
        "models": ("kimi-k3.1-pro", "kimi-k3"),
    },
    "volcengine": {
        "name": "Volcengine Ark Official Direct",
        "family": "Volcengine",
        "protocol": "openai",
        "endpoint": "https://ark.cn-beijing.volces.com/api/v3/chat/completions",
        "models": ("doubao-seed-2.1-turbo",),
    },
    "zhipu": {
        "name": "Zhipu GLM Official Direct",
        "family": "Zhipu",
        "protocol": "openai",
        "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "models": ("glm-5.3",),
    },
    "deepseek": {
        "name": "DeepSeek Official Direct",
        "family": "DeepSeek",
        "protocol": "openai",
        "endpoint": "https://api.deepseek.com/chat/completions",
        "models": ("deepseek-v4.1-pro", "deepseek-v4.1-flash"),
    },
    "minimax": {
        "name": "MiniMax Official Direct",
        "family": "MiniMax",
        "protocol": "openai",
        "endpoint": "https://api.minimax.chat/v1/text/chatcompletion_v2",
        "models": ("minimax-m3",),
    },
    "bailian": {
        "name": "Alibaba Model Studio (Bailian) Official Direct",
        "family": "Alibaba",
        "protocol": "openai",
        "endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "models": ("qwen3.8-max",),
    },
    "xiaomi": {
        "name": "Xiaomi MiMo Official Direct",
        "family": "Xiaomi",
        "protocol": "openai",
        "endpoint": "https://api.mimo.xiaomi.com/v1/chat/completions",
        "models": ("mimo-v2.6-pro",),
    },
}

NAMED_PRIMARY_BUCKETS = frozenset(b for b in PROBE_BUCKETS if b != "other")
BATTERY_SIZE = len(PROBE_PROMPTS_POOL)  # 14 prompts
BATTERY_TOKEN_BUDGET_HARD_CAP = 30000   # 30,000 tokens per 14-probe battery


def get_engine_commit_sha() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
            timeout=3.0,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            return res.stdout.strip()
    except Exception:
        pass
    return "unknown"


def get_prompt_pool_sha256() -> str:
    canonical = json.dumps(list(PROBE_PROMPTS_POOL), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_calibration_target(
    provider_slug: str,
    claimed_model: str,
    mode: str,
    samples: int,
    mock_base_url: str = None,
) -> tuple:
    """
    Validate provider official-direct eligibility, model-provider pairing,
    mode ("baseline" vs "smoke"), and sample count constraints.
    Returns (endpoint_url, protocol, provider_meta).
    """
    provider_slug = (provider_slug or "").strip()
    claimed_model = (claimed_model or "").strip()
    mode = (mode or "baseline").strip().lower()

    if mode not in ("baseline", "smoke"):
        raise ValueError(f"INVALID_MODE: mode must be 'baseline' or 'smoke', got '{mode}'.")

    if provider_slug in EXCLUDED_NON_DIRECT_PROVIDERS:
        raise ValueError(
            f"PROVIDER_NOT_OFFICIAL_DIRECT: '{provider_slug}' 是聚合/工具壳订阅端点，"
            f"严禁用于官方直连基线校准。允许的官方直连服务商: {sorted(OFFICIAL_DIRECT_PROVIDERS.keys())}"
        )

    if provider_slug not in OFFICIAL_DIRECT_PROVIDERS:
        raise ValueError(
            f"UNKNOWN_DIRECT_PROVIDER: '{provider_slug}' 不在官方直连白名单内。"
            f"允许的官方直连服务商: {sorted(OFFICIAL_DIRECT_PROVIDERS.keys())}"
        )

    prov_meta = OFFICIAL_DIRECT_PROVIDERS[provider_slug]
    allowed_models = prov_meta["models"]
    if claimed_model not in allowed_models:
        raise ValueError(
            f"MODEL_PROVIDER_MISMATCH: 模型 '{claimed_model}' 不属于服务商 '{provider_slug}' 的官方直连模型池 "
            f"{list(allowed_models)}。"
        )

    if samples <= 0 or (samples % BATTERY_SIZE != 0):
        raise ValueError(
            f"INVALID_SAMPLE_COUNT: samples ({samples}) 必须为提示词池容量 ({BATTERY_SIZE}) 的正整数倍，"
            f"以保证 {BATTERY_SIZE} 条提示词均匀轮转（例如 210 = 15×14）。"
        )

    if mode == "baseline" and samples < 200:
        raise ValueError(
            f"INVALID_SAMPLE_COUNT: baseline 校准模式要求样本量 N >= 200 且为 {BATTERY_SIZE} 的整数倍（最小 N=210），"
            f"当前传入 samples={samples}。"
        )

    if mode == "smoke" and samples < BATTERY_SIZE:
        raise ValueError(
            f"INVALID_SAMPLE_COUNT: smoke 模式要求样本量 N >= {BATTERY_SIZE} 且为 {BATTERY_SIZE} 的整数倍，"
            f"当前传入 samples={samples}。"
        )

    # Resolve endpoint URL
    if mock_base_url:
        if mode != "smoke":
            raise ValueError("MOCK_ENDPOINT_FORBIDDEN: baseline 模式严禁使用 --mock-base-url，仅允许官方直连端点。")
        parsed = urllib.parse.urlparse(mock_base_url)
        if parsed.scheme not in ("http", "https") or parsed.hostname not in ("127.0.0.1", "localhost"):
            raise ValueError("MOCK_ENDPOINT_FORBIDDEN: --mock-base-url 仅限 smoke 模式连接本机 127.0.0.1/localhost。")
        endpoint_url = f"{mock_base_url.rstrip('/')}/{provider_slug}"
    else:
        if provider_slug in ALLOWED_PROVIDERS:
            endpoint_url = ALLOWED_PROVIDERS[provider_slug]["endpoint"]
        else:
            endpoint_url = prov_meta["endpoint"]

    return endpoint_url, prov_meta["protocol"], prov_meta


def run_calibration(
    provider_slug: str,
    claimed_model: str,
    api_key: str,
    samples: int = 210,
    mode: str = "baseline",
    output_path: str = None,
    mock_base_url: str = None,
    quiet: bool = False,
) -> dict:
    """
    Execute N distribution probes against the official direct endpoint with:
    - temperature = 1.0, max_tokens = 256, concurrency = 4
    - uniform cycling over all 14 prompts in PROBE_PROMPTS_POOL
    - strict valid-extraction sufficiency check (>= ceil(N * 8 / 14))
    - proportional 30,000-token-per-battery budget enforcement
    - full per-probe telemetry & run_conditions persisted in the returned/saved dict
    """
    if not api_key or len(api_key.strip()) < 6:
        raise ValueError("INVALID_API_KEY: 未读取到有效的官方 API Key（请检查环境变量设置）。")

    endpoint_url, protocol, prov_meta = validate_calibration_target(
        provider_slug=provider_slug,
        claimed_model=claimed_model,
        mode=mode,
        samples=samples,
        mock_base_url=mock_base_url,
    )

    temperature = 1.0
    max_tokens = 256
    concurrency = 4
    num_batteries = samples // BATTERY_SIZE
    token_budget_cap = num_batteries * BATTERY_TOKEN_BUDGET_HARD_CAP

    if not quiet:
        print(f"[*] Mode: {mode} | Provider: {provider_slug} ({prov_meta['name']}) | Model: {claimed_model}")
        print(f"[*] Official Endpoint: {endpoint_url}")
        print(f"[*] Samples: {samples} ({num_batteries} batteries x {BATTERY_SIZE} prompts, concurrency={concurrency})")

    indexed_results = [None] * samples
    t0 = time.perf_counter()

    def _run_one(probe_idx: int) -> tuple:
        prompt_idx = probe_idx % BATTERY_SIZE
        prompt_text = PROBE_PROMPTS_POOL[prompt_idx]
        res = _call_single_upstream_probe(
            endpoint_url,
            protocol,
            api_key,
            claimed_model,
            prompt_text,
            temperature,
            max_tokens,
        )
        return probe_idx, prompt_idx, prompt_text, res

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
            futs = [pool.submit(_run_one, i) for i in range(samples)]
            for f in concurrent.futures.as_completed(futs):
                p_idx, pr_idx, pr_text, r = f.result()
                indexed_results[p_idx] = (p_idx, pr_idx, pr_text, r)
    finally:
        api_key = None

    total_elapsed_s = round(max(0.001, time.perf_counter() - t0), 3)

    counts = {k: 0.0 for k in PROBE_BUCKETS}
    probe_records = []
    extracted_tokens = []
    http_ok_count = 0
    http_failure_count = 0
    rate_429_count = 0
    valid_extracted_count = 0
    empty_content_count = 0
    total_prompt_tokens = 0
    total_completion_tokens = 0
    total_cached_tokens = 0

    for p_idx, pr_idx, pr_text, r in indexed_results:
        ok = bool(r.get("ok"))
        status_code = int(r.get("status_code") or 0)
        elapsed_ms = round(float(r.get("elapsed_s") or 0.0) * 1000.0, 2)
        if r.get("is_429") or status_code == 429:
            rate_429_count += 1

        if not ok:
            http_failure_count += 1
            probe_records.append(
                {
                    "probe_index": p_idx,
                    "prompt_index": pr_idx,
                    "prompt_text": pr_text,
                    "ok": False,
                    "status_code": status_code,
                    "elapsed_ms": elapsed_ms,
                    "raw_text": "",
                    "had_reasoning": False,
                    "extracted_token": "",
                    "assigned_bucket": None,
                    "usage": {"prompt_tokens": 0, "completion_tokens": 0, "cached_tokens": 0},
                    "error": r.get("error", f"HTTP_{status_code}"),
                }
            )
            continue

        http_ok_count += 1
        raw_text = str(r.get("text") or "").strip()
        reasoning_text = str(r.get("reasoning") or r.get("reasoning_content") or "").strip()
        tok = r.get("extracted_token")
        if tok is None:
            tok = extract_number_from_reasoning_or_content(raw_text, reasoning_text)
        tok = str(tok or "").strip()

        p_toks = int(r.get("prompt_tokens") or 0)
        c_toks = int(r.get("completion_tokens") or 0)
        cache_toks = int(r.get("cached_tokens") or 0)
        total_prompt_tokens += p_toks
        total_completion_tokens += c_toks
        total_cached_tokens += cache_toks

        if not tok:
            empty_content_count += 1
            assigned_bucket = None
        else:
            valid_extracted_count += 1
            extracted_tokens.append(tok)
            assigned_bucket = tok if tok in NAMED_PRIMARY_BUCKETS else "other"
            counts[assigned_bucket] += 1.0

        probe_records.append(
            {
                "probe_index": p_idx,
                "prompt_index": pr_idx,
                "prompt_text": pr_text,
                "ok": True,
                "status_code": status_code,
                "elapsed_ms": elapsed_ms,
                "raw_text": raw_text,
                "had_reasoning": bool(reasoning_text or ("<think>" in raw_text)),
                "extracted_token": tok,
                "assigned_bucket": assigned_bucket,
                "usage": {
                    "prompt_tokens": p_toks,
                    "completion_tokens": c_toks,
                    "cached_tokens": cache_toks,
                },
                "error": None,
            }
        )

    total_tokens_consumed = total_prompt_tokens + total_completion_tokens
    if total_tokens_consumed > token_budget_cap:
        raise RuntimeError(
            f"PROBE_TOKEN_BUDGET_EXCEEDED: 实际总消耗 Token ({total_tokens_consumed}) 超过硬顶预算 "
            f"({token_budget_cap} tokens = {num_batteries} batteries × {BATTERY_TOKEN_BUDGET_HARD_CAP})。"
        )

    min_required_valid = max(8, math.ceil(samples * 8.0 / float(BATTERY_SIZE)))
    if valid_extracted_count < min_required_valid:
        first_err = next((rec["error"] for rec in probe_records if rec.get("error")), "EMPTY_EXTRACTION")
        raise RuntimeError(
            f"INSUFFICIENT_PROBE_CONTENT: 有效整数提取样本数不足 "
            f"({valid_extracted_count}/{samples} < 最低门槛 {min_required_valid}/{samples}；"
            f"HTTP成功={http_ok_count}，空提取={empty_content_count}，HTTP失败={http_failure_count}，首错={first_err})。"
            "拒绝生成或落盘不合格校准归档。"
        )

    measured_dist = normalize_dist(counts)

    prior_meta = GOLDEN_BASELINES[claimed_model]
    prior_dist = prior_meta["dist"]
    jsd_to_prior = compute_jsd(measured_dist, prior_dist)
    sim_to_prior = round(max(0.0, (1.0 - jsd_to_prior) * 100.0), 1)

    eligible_for_baseline = bool(
        mode == "baseline"
        and not mock_base_url
        and samples >= 200
        and (samples % BATTERY_SIZE == 0)
        and valid_extracted_count >= min_required_valid
    )

    report = {
        "schema": "csl-meter-calibration-archive/v1.3.7",
        "timestamp_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "run_conditions": {
            "mode": mode,
            "eligible_for_golden_baseline": eligible_for_baseline,
            "provider_slug": provider_slug,
            "provider_name": prov_meta["name"],
            "model_family": prov_meta["family"],
            "claimed_model": claimed_model,
            "endpoint_url": endpoint_url,
            "protocol": protocol,
            "temperature": temperature,
            "max_tokens": max_tokens,
            "top_p_sent": False,
            "concurrency": concurrency,
            "prompt_pool_size": BATTERY_SIZE,
            "prompt_pool_sha256": get_prompt_pool_sha256(),
            "engine_commit_sha": get_engine_commit_sha(),
        },
        "summary_metrics": {
            "total_probes": samples,
            "http_ok_probes": http_ok_count,
            "http_failed_probes": http_failure_count,
            "rate_429_count": rate_429_count,
            "valid_extracted_samples": valid_extracted_count,
            "min_required_valid_samples": min_required_valid,
            "empty_extraction_count": empty_content_count,
            "total_elapsed_s": total_elapsed_s,
            "total_prompt_tokens": total_prompt_tokens,
            "total_completion_tokens": total_completion_tokens,
            "total_cached_tokens": total_cached_tokens,
            "total_tokens_consumed": total_tokens_consumed,
            "token_budget_hard_cap": token_budget_cap,
        },
        "raw_counts": counts,
        "measured_distribution": measured_dist,
        "comparison_with_uncalibrated_engine_prior": {
            "engine_prior_status": "uncalibrated_prior_in_code",
            "baseline_model": claimed_model,
            "engine_prior_distribution": prior_dist,
            "jsd_to_engine_prior": round(jsd_to_prior, 4),
            "similarity_to_engine_prior_pct": sim_to_prior,
        },
        "extracted_tokens": extracted_tokens,
        "probe_records": probe_records,
    }

    if not quiet:
        print(f"[+] Probes completed in {total_elapsed_s:.2f}s: valid_extracted={valid_extracted_count}/{samples}")
        for k in PROBE_BUCKETS:
            bar = "#" * int(measured_dist[k] * 40)
            print(f"  Bucket {k:5s}: {measured_dist[k]:.4f} (count={int(counts[k]):3d}) {bar}")
        print(f"[+] JSD vs uncalibrated engine prior: {jsd_to_prior:.4f} (similarity: {sim_to_prior:.1f}%)")

    if output_path:
        abs_out = os.path.abspath(output_path)
        os.makedirs(os.path.dirname(abs_out), exist_ok=True)
        with open(abs_out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        if not quiet:
            print(f"[+] Full calibration archive written to: {abs_out}")

    return report


class _SelfTestMockHandler(BaseHTTPRequestHandler):
    """Local mock server for --self-test smoke verification."""

    mode = "valid_kimi"

    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        _ = self.rfile.read(length)
        if _SelfTestMockHandler.mode == "empty_thinking":
            resp_obj = {
                "id": "chatcmpl-empty",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "", "reasoning_content": "Still thinking without numbers..."}}],
                "usage": {"prompt_tokens": 22, "completion_tokens": 256},
            }
        else:
            seq = ["37", "73", "42", "37", "47", "73", "37", "42", "7", "53", "67", "88", "23", "91"]
            idx = getattr(_SelfTestMockHandler, "_counter", 0)
            _SelfTestMockHandler._counter = idx + 1
            pick = seq[idx % len(seq)]
            resp_obj = {
                "id": f"chatcmpl-test-{idx}",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "",
                            "reasoning_content": f"The user asked for a random integer from 1 to 100. I will choose {pick}.",
                        },
                    }
                ],
                "usage": {"prompt_tokens": 24, "completion_tokens": 38, "prompt_tokens_details": {"cached_tokens": 16}},
            }
        raw_bytes = json.dumps(resp_obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(raw_bytes)


def run_self_test() -> dict:
    """
    Execute an end-to-end smoke test verifying all 9 review criteria.
    """
    mapped_models = {}
    for p_slug, p_meta in OFFICIAL_DIRECT_PROVIDERS.items():
        assert p_slug not in EXCLUDED_NON_DIRECT_PROVIDERS
        for m in p_meta["models"]:
            mapped_models[m] = p_slug
    assert set(mapped_models.keys()) == set(GOLDEN_BASELINES.keys()), (
        f"Mismatch between OFFICIAL_DIRECT_PROVIDERS models and GOLDEN_BASELINES: "
        f"{set(mapped_models.keys()) ^ set(GOLDEN_BASELINES.keys())}"
    )

    for bad_prov in ("opencode", "commandcode", "kilo", "cursor", "kiro", "copilot"):
        try:
            validate_calibration_target(bad_prov, "kimi-k3.1-pro", "baseline", 210)
            raise AssertionError(f"Expected {bad_prov} to be rejected")
        except ValueError as e:
            assert "PROVIDER_NOT_OFFICIAL_DIRECT" in str(e)

    try:
        validate_calibration_target("openai", "kimi-k3.1-pro", "baseline", 210)
        raise AssertionError("Expected model mismatch to be rejected")
    except ValueError as e:
        assert "MODEL_PROVIDER_MISMATCH" in str(e)

    for bad_n in (50, 100, 196, 200):
        try:
            validate_calibration_target("kimi", "kimi-k3.1-pro", "baseline", bad_n)
            raise AssertionError(f"Expected bad_n={bad_n} to be rejected in baseline mode")
        except ValueError as e:
            assert "INVALID_SAMPLE_COUNT" in str(e)

    server = ThreadingHTTPServer(("127.0.0.1", 0), _SelfTestMockHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        _SelfTestMockHandler.mode = "valid_kimi"
        _SelfTestMockHandler._counter = 0
        with tempfile.TemporaryDirectory() as tmpdir:
            out_json = os.path.join(tmpdir, "smoke_archive.json")
            _ = run_calibration(
                provider_slug="kimi",
                claimed_model="kimi-k3.1-pro",
                api_key="sk-ephemeral-self-test-key",
                samples=28,
                mode="smoke",
                output_path=out_json,
                mock_base_url=f"http://127.0.0.1:{port}",
                quiet=True,
            )
            assert os.path.exists(out_json)
            with open(out_json, "r", encoding="utf-8") as f:
                saved = json.load(f)
            assert saved["run_conditions"]["mode"] == "smoke"
            assert saved["run_conditions"]["eligible_for_golden_baseline"] is False
            assert saved["run_conditions"]["temperature"] == 1.0
            assert saved["run_conditions"]["max_tokens"] == 256
            assert saved["run_conditions"]["top_p_sent"] is False
            assert saved["run_conditions"]["prompt_pool_size"] == 14
            assert len(saved["probe_records"]) == 28
            assert len(saved["extracted_tokens"]) == 28
            assert saved["summary_metrics"]["valid_extracted_samples"] == 28
            assert saved["probe_records"][0]["had_reasoning"] is True
            assert saved["probe_records"][0]["usage"]["prompt_tokens"] == 24

            _SelfTestMockHandler.mode = "empty_thinking"
            unwritten_json = os.path.join(tmpdir, "should_not_exist.json")
            try:
                run_calibration(
                    provider_slug="kimi",
                    claimed_model="kimi-k3.1-pro",
                    api_key="sk-ephemeral-self-test-key",
                    samples=14,
                    mode="smoke",
                    output_path=unwritten_json,
                    mock_base_url=f"http://127.0.0.1:{port}",
                    quiet=True,
                )
                raise AssertionError("Expected INSUFFICIENT_PROBE_CONTENT to be raised")
            except RuntimeError as e:
                assert "INSUFFICIENT_PROBE_CONTENT" in str(e)
            assert not os.path.exists(unwritten_json)
    finally:
        server.shutdown()
        server.server_close()

    doc_path = os.path.join(REPO_ROOT, "docs", "golden_baselines_calibration.md")
    doc_table_validation = "passed"
    if not os.path.exists(doc_path):
        # Non-blocking (review v1.3.7 note): doc missing -> skip table
        # validation, report the skip instead of silently passing.
        doc_table_validation = "skipped: doc missing"
        print(f"WARNING: doc table validation skipped, doc missing: {doc_path}", file=sys.stderr)
    else:
        with open(doc_path, "r", encoding="utf-8") as f:
            doc_text = f.read()
        matched_models = 0
        mismatched_models = []
        for line in doc_text.splitlines():
            line_s = line.strip()
            if line_s.startswith("|") and "`" in line_s:
                parts = [c.strip() for c in line_s.strip("|").split("|")]
                if len(parts) >= 14 and parts[1].startswith("`") and parts[1].endswith("`"):
                    m_id = parts[1].strip("`")
                    if m_id in GOLDEN_BASELINES:
                        vals = [round(float(parts[4 + idx]), 4) for idx in range(10)]
                        expected_vals = [round(float(GOLDEN_BASELINES[m_id]["dist"][b]), 4) for b in PROBE_BUCKETS]
                        if vals != expected_vals:
                            mismatched_models.append(m_id)
                        else:
                            matched_models += 1
        if mismatched_models or matched_models != len(GOLDEN_BASELINES):
            # Non-blocking: doc table incomplete/stale -> warn and skip,
            # do not fail the self-test on a documentation issue.
            doc_table_validation = (
                f"warning: matched {matched_models}/{len(GOLDEN_BASELINES)} models"
                + (f", mismatched: {','.join(mismatched_models)}" if mismatched_models else "")
            )
            print(f"WARNING: doc table validation {doc_table_validation}", file=sys.stderr)

    summary = {
        "self_test_passed": True,
        "doc_table_validation": doc_table_validation,
        "official_direct_providers_count": len(OFFICIAL_DIRECT_PROVIDERS),
        "golden_baselines_models_verified": len(GOLDEN_BASELINES),
        "prompt_pool_size_verified": BATTERY_SIZE,
        "smoke_probes_verified": 28,
        "insufficient_content_rejection_verified": True,
    }
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return summary


def main():
    parser = argparse.ArgumentParser(
        description="Calibrate CSL-Meter Golden Baselines against official first-party direct endpoints."
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="Run built-in end-to-end verification and smoke test suite",
    )
    parser.add_argument(
        "--provider",
        help=f"Official direct provider slug: {sorted(OFFICIAL_DIRECT_PROVIDERS.keys())}",
    )
    parser.add_argument(
        "--model",
        help="Claimed model ID paired with the official provider (e.g. kimi-k3.1-pro, gpt-5.6-sol, deepseek-v4.1-pro)",
    )
    parser.add_argument(
        "--api-key-env",
        default="CSL_CALIBRATION_API_KEY",
        help="Environment variable name holding the official API key (default: CSL_CALIBRATION_API_KEY)",
    )
    parser.add_argument(
        "--mode",
        choices=("baseline", "smoke"),
        default="baseline",
        help="Run mode: 'baseline' requires N>=210 (multiple of 14) on official direct endpoint; 'smoke' allows N>=14 (multiple of 14)",
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=210,
        help="Number of probes N; must be a multiple of 14 (default: 210 = 15 x 14 for baseline mode)",
    )
    parser.add_argument(
        "--output",
        help="Output JSON path for the full reproducible calibration archive",
    )
    parser.add_argument(
        "--mock-base-url",
        help="Localhost mock base URL (strictly restricted to --mode smoke on 127.0.0.1/localhost)",
    )
    args = parser.parse_args()

    if args.self_test:
        run_self_test()
        return

    if not args.provider or not args.model:
        parser.error("--provider and --model are required unless --self-test is specified.")

    env_var_name = (args.api_key_env or "CSL_CALIBRATION_API_KEY").strip()
    api_key = os.environ.get(env_var_name, "").strip()
    if not api_key:
        raise SystemExit(
            f"ERROR: Environment variable '{env_var_name}' is not set or empty. "
            f"Pass the API key via '{env_var_name}=sk-... python3 scripts/calibrate_golden_baselines.py ...' "
            "to keep credentials out of shell history and process argv."
        )

    run_calibration(
        provider_slug=args.provider,
        claimed_model=args.model,
        api_key=api_key,
        samples=args.samples,
        mode=args.mode,
        output_path=args.output,
        mock_base_url=args.mock_base_url,
    )


if __name__ == "__main__":
    main()
