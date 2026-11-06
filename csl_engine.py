#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSL-Meter Core Engine (v1.3 - Real Outbound Probe Engine + Strict Demo/Verified Isolation)
- Real outbound HTTPS calls to whitelisted official provider endpoints (<=4 concurrency;
  per-battery hard budget PROBE_TOKEN_BUDGET = 30,000 tokens on real upstream usage —
  user ruling 2026-11-06, superseding the PRD v1.2 figure of <3,000 tokens per battery)
- Strict separation between 'Server-Verified' (real completed API probes) and 'Simulated · 模拟生成' (demo seed data)
- Zero credential retention (API key used in memory for outbound HTTP only, overwritten in finally)
"""

import concurrent.futures
import hashlib
import json
import math
import os
import random
import re
import shutil
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

SITE_DOMAIN = "https://konspace.cc"
API_DOMAIN = "https://api.konspace.cc"
BRAND_NAME = "CSL-Meter"
BRAND_FULL = "CSL-Meter (Consistency, Substitution & Latency Meter)"

_EPHEMERAL_SALT = os.urandom(32).hex()

# Optional test-only hook for unit testing real HTTP socket calls against a local mock server
# Never set in production (None by default).
_TEST_UPSTREAM_BASE_URL = None

# Per-battery hard token budget, enforced on REAL upstream usage
# (prompt + completion tokens as reported by the provider). Exceeding the
# cap aborts the battery with an error and no report is filed.
# User ruling 2026-11-06: a few thousand tokens per battery is not a
# constraint worth strangling reasoning models with — the cap is 30,000.
# This supersedes the PRD v1.2 figure of <3,000 tokens per battery; do not
# claim compliance with the 3,000 figure anywhere.
PROBE_TOKEN_BUDGET = 30000

# Strict SSRF Whitelist: Only official provider endpoints from PRD Section 2 are permitted.
ALLOWED_PROVIDERS = {
    "volcengine": {
        "name": "火山引擎方舟 (Volcengine Ark)",
        "region": "cn",
        "protocol": "openai",
        "endpoint": "https://ark.cn-beijing.volces.com/api/v3/chat/completions",
        "host": "ark.cn-beijing.volces.com",
    },
    "kimi": {
        "name": "Kimi (月之暗面 Moonshot)",
        "region": "cn",
        "protocol": "openai",
        "endpoint": "https://api.moonshot.cn/v1/chat/completions",
        "host": "api.moonshot.cn",
    },
    "zhipu": {
        "name": "智谱清言 (Zhipu GLM)",
        "region": "cn",
        "protocol": "openai",
        "endpoint": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        "host": "open.bigmodel.cn",
    },
    "minimax": {
        "name": "MiniMax 开放平台",
        "region": "cn",
        "protocol": "openai",
        "endpoint": "https://api.minimax.chat/v1/text/chatcompletion_v2",
        "host": "api.minimax.chat",
    },
    "bailian": {
        "name": "阿里云百炼 (Alibaba Model Studio)",
        "region": "cn",
        "protocol": "openai",
        "endpoint": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        "host": "dashscope.aliyuncs.com",
    },
    "xiaomi": {
        "name": "小米 MiMo (Xiaomi AI)",
        "region": "cn",
        "protocol": "openai",
        "endpoint": "https://api.mimo.xiaomi.com/v1/chat/completions",
        "host": "api.mimo.xiaomi.com",
    },
    "openai": {
        "name": "OpenAI Official",
        "region": "global_oa",
        "protocol": "openai",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "host": "api.openai.com",
    },
    "anthropic": {
        "name": "Anthropic Official",
        "region": "global_oa",
        "protocol": "anthropic",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "host": "api.anthropic.com",
    },
    "xai": {
        "name": "xAI (Grok Official)",
        "region": "global_oa",
        "protocol": "openai",
        "endpoint": "https://api.x.ai/v1/chat/completions",
        "host": "api.x.ai",
    },
    "opencode": {
        "name": "OpenCode Console",
        "region": "global_coding",
        "protocol": "openai",
        # v1.3.3: the catalog plans are Go *subscription* plans, so probes must
        # ride the Go subscription rail (/zen/go/v1), not the pay-as-you-go
        # Zen rail (/zen/v1) — the real subscription account holds no PAYG
        # balance there (production-verified 2026-11-06: 14/14 probes HTTP 402).
        "endpoint": "https://opencode.ai/zen/go/v1/chat/completions",
        "host": "opencode.ai",
        # The Go gateway rejects session-less requests (HTTP 400
        # MissingSessionID, production-verified 2026-11-06); the probe
        # battery sends this header with one fresh id per battery.
        "session_header": "x-opencode-session",
    },
    "commandcode": {
        "name": "Command Code Studio",
        "region": "global_coding",
        "protocol": "openai",
        "endpoint": "https://api.commandcode.ai/v1/chat/completions",
        "host": "api.commandcode.ai",
    },
    "kilo": {
        "name": "Kilo Gateway (Kilo Pass)",
        "region": "global_coding",
        "protocol": "openai",
        "endpoint": "https://api.kilo.ai/v1/chat/completions",
        "host": "api.kilo.ai",
    },
    "cursor": {
        "name": "Cursor Personal (IDE Harness)",
        "region": "global_coding",
        "protocol": "openai",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "host": "api.openai.com",
    },
    "kiro": {
        "name": "Kiro Personal (Spec IDE Harness)",
        "region": "global_coding",
        "protocol": "anthropic",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "host": "api.anthropic.com",
    },
    "copilot": {
        "name": "GitHub Copilot Pro (Personal)",
        "region": "global_coding",
        "protocol": "openai",
        "endpoint": "https://api.githubcopilot.com/chat/completions",
        "host": "api.githubcopilot.com",
    },
}

PROBE_BUCKETS = ["42", "37", "47", "73", "7", "53", "67", "23", "88", "other"]

# Dynamic paraphrase pool for low-entropy single-token numerical probing (14 queries per run)
PROBE_PROMPTS_POOL = [
    "Pick a random integer between 1 and 100. Output ONLY the digits, nothing else.",
    "请随机说出一个 1 到 100 之间的整数，只输出数字本身，不要任何标点或解释。",
    "Name one random number from 1 to 100. Reply with the integer only.",
    "从 1 至 100 中任选一个整数，仅返回阿拉伯数字。",
    "Choose a random whole number in [1, 100]. Output just the number.",
    "随机生成一个 1~100 的整数，只回答数字。",
    "Give me a single random integer between 1 and 100 (digits only).",
    "请立即给出一个 1 到 100 范围内的随机整数，仅输出数字。",
    "Select an integer at random from 1 to 100. Output only the number.",
    "在 1 到 100 之间盲选一个数字，只打印该数字。",
    "Write one random integer between 1 and 100. No words, just digits.",
    "随便报一个 1 到 100 以内的整数，只输出数字。",
    "Output a single random number between 1 and 100, digits only.",
    "请输出 1 到 100 之间的任意一个整数（仅限数字）。",
]

# Fixed ~180-token mixed Chinese + code snippet for Tokenizer & Cache Audit (sent twice)
TOKENIZER_AUDIT_PROMPT = (
    "请统计以下函数中的分支数量，仅输出一个整数数字：\n"
    "def calc_tier_quota(tokens_used: int, window_hours: int = 5) -> str:\n"
    "    # 计算个人订阅套餐在 5 小时滚动窗口内的额度水位与缓冲系数\n"
    "    if tokens_used <= 0:\n"
    "        return 'idle'\n"
    "    elif tokens_used < 150000:\n"
    "        return 'window_early'\n"
    "    elif tokens_used < 450000:\n"
    "        return 'window_mid'\n"
    "    else:\n"
    "        return 'window_late'\n"
    "只输出分支数量对应的阿拉伯数字。"
)
EXPECTED_AUDIT_PROMPT_TOKENS = 112  # gpt-5.4 / o200k_base reference token count

GOLDEN_BASELINES = {
    "gpt-5.6-sol": {
        "family": "OpenAI",
        "compression_vs_gpt54": 100.0,
        "dist": {"42": 0.28, "37": 0.22, "47": 0.08, "73": 0.16, "7": 0.09, "53": 0.04, "67": 0.04, "23": 0.04, "88": 0.02, "other": 0.03},
    },
    "gpt-6-astra": {
        "family": "OpenAI",
        "compression_vs_gpt54": 100.0,
        "dist": {"42": 0.25, "37": 0.24, "47": 0.09, "73": 0.18, "7": 0.08, "53": 0.05, "67": 0.03, "23": 0.04, "88": 0.01, "other": 0.03},
    },
    "gpt-5.6-luna": {
        "family": "OpenAI",
        "compression_vs_gpt54": 100.0,
        "dist": {"42": 0.34, "37": 0.14, "47": 0.06, "73": 0.11, "7": 0.16, "53": 0.03, "67": 0.03, "23": 0.05, "88": 0.03, "other": 0.05},
    },
    "claude-opus-5.5": {
        "family": "Anthropic",
        "compression_vs_gpt54": 165.6,
        "dist": {"42": 0.11, "37": 0.16, "47": 0.31, "73": 0.19, "7": 0.05, "53": 0.06, "67": 0.04, "23": 0.04, "88": 0.01, "other": 0.03},
    },
    "claude-sonnet-5": {
        "family": "Anthropic",
        "compression_vs_gpt54": 165.9,
        "dist": {"42": 0.13, "37": 0.15, "47": 0.29, "73": 0.17, "7": 0.06, "53": 0.07, "67": 0.05, "23": 0.04, "88": 0.01, "other": 0.03},
    },
    "claude-haiku-4.5": {
        "family": "Anthropic",
        "compression_vs_gpt54": 203.9,
        "dist": {"42": 0.22, "37": 0.11, "47": 0.19, "73": 0.10, "7": 0.15, "53": 0.05, "67": 0.04, "23": 0.06, "88": 0.03, "other": 0.05},
    },
    "grok-4.7": {
        "family": "xAI",
        "compression_vs_gpt54": 94.4,
        "dist": {"42": 0.36, "37": 0.12, "47": 0.07, "73": 0.14, "7": 0.08, "53": 0.04, "67": 0.09, "23": 0.04, "88": 0.03, "other": 0.03},
    },
    "kimi-k3.1-pro": {
        "family": "Moonshot",
        "compression_vs_gpt54": 90.1,
        "dist": {"42": 0.15, "37": 0.26, "47": 0.11, "73": 0.21, "7": 0.07, "53": 0.05, "67": 0.05, "23": 0.03, "88": 0.04, "other": 0.03},
    },
    "kimi-k3": {
        "family": "Moonshot",
        "compression_vs_gpt54": 90.1,
        "dist": {"42": 0.16, "37": 0.25, "47": 0.12, "73": 0.20, "7": 0.07, "53": 0.05, "67": 0.05, "23": 0.03, "88": 0.04, "other": 0.03},
    },
    "doubao-seed-2.1-turbo": {
        "family": "Volcengine",
        "compression_vs_gpt54": 100.9,
        "dist": {"42": 0.19, "37": 0.18, "47": 0.08, "73": 0.12, "7": 0.14, "53": 0.06, "67": 0.06, "23": 0.05, "88": 0.08, "other": 0.04},
    },
    "glm-5.3": {
        "family": "Zhipu",
        "compression_vs_gpt54": 95.7,
        "dist": {"42": 0.14, "37": 0.19, "47": 0.09, "73": 0.15, "7": 0.11, "53": 0.12, "67": 0.07, "23": 0.04, "88": 0.05, "other": 0.04},
    },
    "deepseek-v4.1-pro": {
        "family": "DeepSeek",
        "compression_vs_gpt54": 95.3,
        "dist": {"42": 0.5619047485260774, "37": 0.15714285340136064, "47": 0.057142855782312964, "73": 0.16190475804988672, "7": 4.76190464852608e-09, "53": 4.76190464852608e-09, "67": 4.76190464852608e-09, "23": 4.76190464852608e-09, "88": 4.76190464852608e-09, "other": 0.06190476043083904},
    },
    "deepseek-v4.1-flash": {
        "family": "DeepSeek",
        "compression_vs_gpt54": 95.3,
        "dist": {"42": 0.22380951954648534, "37": 0.11428571210884358, "47": 0.2047619008616781, "73": 0.414285706394558, "7": 0.004761904671201816, "53": 4.7619046712018155e-09, "67": 4.7619046712018155e-09, "23": 4.7619046712018155e-09, "88": 4.7619046712018155e-09, "other": 0.03809523736961453},
    },
    "minimax-m3": {
        "family": "MiniMax",
        "compression_vs_gpt54": 90.5,
        "dist": {"42": 0.18, "37": 0.15, "47": 0.10, "73": 0.14, "7": 0.12, "53": 0.08, "67": 0.08, "23": 0.06, "88": 0.05, "other": 0.04},
    },
    "qwen3.8-max": {
        "family": "Alibaba",
        "compression_vs_gpt54": 95.4,
        "dist": {"42": 0.20, "37": 0.21, "47": 0.09, "73": 0.15, "7": 0.10, "53": 0.06, "67": 0.05, "23": 0.04, "88": 0.06, "other": 0.04},
    },
    "mimo-v2.6-pro": {
        "family": "Xiaomi",
        "compression_vs_gpt54": 101.2,
        "dist": {"42": 0.21, "37": 0.17, "47": 0.10, "73": 0.14, "7": 0.11, "53": 0.07, "67": 0.06, "23": 0.05, "88": 0.05, "other": 0.04},
    },
}

HARNESS_BIAS_VECTORS = {
    "raw": {"42": 0.0, "37": 0.0, "47": 0.0, "73": 0.0, "7": 0.0, "53": 0.0, "67": 0.0, "23": 0.0, "88": 0.0, "other": 0.0},
    "claude-code": {"42": 0.05, "37": -0.02, "47": -0.04, "73": 0.01, "7": 0.02, "53": -0.01, "67": 0.0, "23": -0.01, "88": 0.0, "other": 0.0},
    "cursor": {"42": 0.04, "37": 0.01, "47": -0.03, "73": -0.01, "7": 0.02, "53": 0.0, "67": -0.01, "23": 0.0, "88": -0.01, "other": -0.01},
    "opencode": {"42": 0.02, "37": 0.01, "47": -0.01, "73": 0.0, "7": 0.01, "53": -0.01, "67": -0.01, "23": 0.0, "88": -0.01, "other": 0.0},
    "kimi-cli": {"42": 0.01, "37": 0.02, "47": -0.01, "73": 0.01, "7": -0.01, "53": -0.01, "67": 0.0, "23": 0.0, "88": -0.01, "other": 0.0},
    "kiro": {"42": 0.03, "37": -0.01, "47": -0.02, "73": 0.01, "7": 0.01, "53": 0.0, "67": -0.01, "23": -0.01, "88": 0.0, "other": 0.0},
    "ark-auto": {"42": 0.03, "37": -0.01, "47": -0.01, "73": -0.01, "7": 0.02, "53": 0.0, "67": 0.0, "23": -0.01, "88": 0.0, "other": -0.01},
}


def normalize_dist(d: dict) -> dict:
    raw = {k: max(1e-6, float(d.get(k, 0.0))) for k in PROBE_BUCKETS}
    total = sum(raw.values())
    return {k: raw[k] / total for k in PROBE_BUCKETS}


def compute_jsd(dist_p: dict, dist_q: dict) -> float:
    p = normalize_dist(dist_p)
    q = normalize_dist(dist_q)
    m = {k: 0.5 * (p[k] + q[k]) for k in PROBE_BUCKETS}

    def kl(a, b):
        s = 0.0
        for k in PROBE_BUCKETS:
            if a[k] > 1e-9 and b[k] > 1e-9:
                s += a[k] * math.log2(a[k] / b[k])
        return s

    val = 0.5 * kl(p, m) + 0.5 * kl(q, m)
    return round(min(1.0, max(0.0, val)), 4)


def de_bias_harness_dist(observed_dist: dict, harness_type: str) -> dict:
    p = normalize_dist(observed_dist)
    bias = HARNESS_BIAS_VECTORS.get(harness_type or "raw", HARNESS_BIAS_VECTORS["raw"])
    corrected = {k: max(0.002, p[k] - bias.get(k, 0.0)) for k in PROBE_BUCKETS}
    return normalize_dist(corrected)


def find_nearest_profiles(net_dist: dict) -> list:
    scored = []
    for model_id, meta in GOLDEN_BASELINES.items():
        jsd = compute_jsd(net_dist, meta["dist"])
        similarity = round(max(0.0, (1.0 - jsd) * 100.0), 1)
        scored.append({"model": model_id, "jsd": jsd, "similarity": similarity, "family": meta["family"]})
    scored.sort(key=lambda x: x["jsd"])
    return scored


def compute_csl_index(net_jsd: float, split_jsd: float, token_ratio: float) -> float:
    term_jsd = max(0.0, (net_jsd - 0.06) / 0.42)
    term_split = max(0.0, (split_jsd - 0.06) / 0.26)
    term_token = min(1.0, max(0.0, (token_ratio - 1.0) / 0.35))
    raw = 0.55 * term_jsd + 0.25 * term_split + 0.20 * term_token
    return round(100.0 * min(1.0, max(0.0, raw)), 1)


def compute_irreversible_key_hash(api_key: str) -> str:
    if not api_key or len(api_key) < 6:
        return "anon-" + uuid.uuid4().hex[:10]
    masked_material = f"{_EPHEMERAL_SALT}:{len(api_key)}:{api_key[:3]}:{api_key[-2:]}"
    return hashlib.sha256(masked_material.encode("utf-8")).hexdigest()[:16]


def validate_ssrf_whitelist(provider_slug: str, custom_url: str = None) -> tuple:
    if custom_url:
        return False, "SSRF_POLICY_BLOCKED: 禁止提交自定义 Base URL 或任意外部地址，仅允许白名单官方端点。"
    if provider_slug not in ALLOWED_PROVIDERS:
        return False, f"SSRF_POLICY_BLOCKED: 服务商 '{provider_slug}' 不在首期官方白名单池内。"
    if _TEST_UPSTREAM_BASE_URL:
        return True, f"{_TEST_UPSTREAM_BASE_URL}/{provider_slug}"
    return True, ALLOWED_PROVIDERS[provider_slug]["endpoint"]


def extract_number_from_reasoning_or_content(content: str, reasoning: str = "") -> str:
    """
    Reasoning-Aware number extractor:
    1. Extracts think blocks if content has inline <think>...</think>.
    2. Inspects content outside of <think> tags for chosen numbers.
    3. If content outside of think tags has no numbers, inspects thinking/reasoning blocks.
    """
    raw_content = content or ""
    inline_think = ""
    if "<think>" in raw_content and "</think>" in raw_content:
        m_think = re.search(r"<think>(.*?)</think>", raw_content, flags=re.DOTALL)
        if m_think:
            inline_think = m_think.group(1).strip()
    elif "<think>" in raw_content:
        inline_think = raw_content.split("<think>", 1)[1].strip()

    cleaned_content = re.sub(r"<think>.*?(?:</think>|$)", "", raw_content, flags=re.DOTALL).strip()
    m_direct = re.search(r"\b(100|[1-9]\d?)\b", cleaned_content)
    if m_direct:
        return m_direct.group(1)

    m_any = re.search(r"\d+", cleaned_content)
    if m_any:
        return m_any.group(0)

    # Fallback to reasoning / thought content
    all_reasoning = f"{reasoning or ''} {inline_think}".strip()
    if all_reasoning:
        # Look for explicit conclusion markers
        m_concl = re.findall(
            r"(?:pick|choose|result|number|integer|output|选择|数字|答案|输出)[^\d]*(\b(?:100|[1-9]\d?)\b)",
            all_reasoning,
            flags=re.IGNORECASE,
        )
        if m_concl:
            return m_concl[-1]
        nums_in_reasoning = re.findall(r"\b(100|[1-9]\d?)\b", all_reasoning)
        if nums_in_reasoning:
            return nums_in_reasoning[-1]
        m_r_any = re.search(r"\d+", all_reasoning)
        if m_r_any:
            return m_r_any.group(0)

    return ""


def _call_single_upstream_probe(
    endpoint_url: str,
    protocol: str,
    api_key: str,
    model_name: str,
    prompt_text: str,
    temperature: float = 1.0,
    max_tokens: int = 16,
    session_header: tuple = None,
) -> dict:
    """
    Execute a single real outbound HTTP/HTTPS request to the whitelisted provider API.
    Never logs or persists api_key. Returns parsed response text, token usage, latency, and status.
    """
    t0 = time.perf_counter()
    if protocol == "anthropic":
        headers = {
            "Content-Type": "application/json",
            "x-api-key": api_key,
            "anthropic-version": "2023-06-01",
            "User-Agent": "CSL-Meter-Auditor/1.3 (+https://konspace.cc)",
        }
        body_dict = {
            "model": model_name,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt_text}],
        }
    else:
        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "CSL-Meter-Auditor/1.3 (+https://konspace.cc)",
        }
        body_dict = {
            "model": model_name,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [{"role": "user", "content": prompt_text}],
        }

    if session_header:
        # Gateway-required per-session header (declared per provider in
        # ALLOWED_PROVIDERS as "session_header"). The id is ephemeral: it is
        # generated per probe battery and is never logged or persisted.
        headers[session_header[0]] = session_header[1]

    req_bytes = json.dumps(body_dict).encode("utf-8")
    req = urllib.request.Request(endpoint_url, data=req_bytes, headers=headers, method="POST")
    ctx = ssl.create_default_context() if endpoint_url.startswith("https://") else None

    try:
        with urllib.request.urlopen(req, timeout=12.0, context=ctx) as resp:
            elapsed_s = max(0.001, time.perf_counter() - t0)
            raw_resp = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw_resp)
            status_code = resp.status
    except urllib.error.HTTPError as he:
        elapsed_s = max(0.001, time.perf_counter() - t0)
        return {
            "ok": False,
            "status_code": he.code,
            "is_429": he.code == 429,
            "elapsed_s": elapsed_s,
            "error": f"HTTP_{he.code}",
        }
    except Exception as exc:
        elapsed_s = max(0.001, time.perf_counter() - t0)
        return {
            "ok": False,
            "status_code": 0,
            "is_429": False,
            "elapsed_s": elapsed_s,
            "error": type(exc).__name__,
        }
    finally:
        headers = None
        api_key = None

    # Parse response text, reasoning content, and token usage across OpenAI & Anthropic formats
    text_out = ""
    reasoning_out = ""
    prompt_tokens = 0
    completion_tokens = 0
    cached_tokens = 0

    if protocol == "anthropic" or ("content" in data and isinstance(data.get("content"), list)):
        blocks = data.get("content", [])
        for b in blocks:
            if isinstance(b, dict):
                b_type = b.get("type")
                if b_type == "text":
                    text_out += b.get("text", "")
                elif b_type in ("thinking", "reasoning"):
                    reasoning_out += b.get("thinking", "") or b.get("text", "")
        usage = data.get("usage") or {}
        prompt_tokens = int(usage.get("input_tokens") or usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("output_tokens") or usage.get("completion_tokens") or 1)
        cached_tokens = int(usage.get("cache_read_input_tokens") or 0)
    else:
        choices = data.get("choices") or []
        if choices and isinstance(choices[0], dict):
            msg = choices[0].get("message") or {}
            text_out = str(msg.get("content") or choices[0].get("text") or "").strip()
            reasoning_out = str(msg.get("reasoning_content") or msg.get("thought") or choices[0].get("reasoning") or "").strip()
            # If reasoning is inline within <think>...</think> in content
            if "<think>" in text_out and "</think>" in text_out:
                think_match = re.search(r"<think>(.*?)</think>", text_out, flags=re.DOTALL)
                if think_match and not reasoning_out:
                    reasoning_out = think_match.group(1).strip()
        usage = data.get("usage") or {}
        prompt_tokens = int(usage.get("prompt_tokens") or 0)
        completion_tokens = int(usage.get("completion_tokens") or 1)
        details = usage.get("prompt_tokens_details") or {}
        cached_tokens = int(details.get("cached_tokens") or usage.get("prompt_cache_hit_tokens") or 0)

    # Extract chosen number token using reasoning-aware heuristic
    extracted_token = extract_number_from_reasoning_or_content(text_out, reasoning_out)

    return {
        "ok": True,
        "status_code": status_code,
        "is_429": False,
        "elapsed_s": elapsed_s,
        "text": text_out.strip(),
        "reasoning": reasoning_out.strip(),
        "extracted_token": extracted_token,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": max(1, completion_tokens),
        "cached_tokens": cached_tokens,
    }


def execute_real_upstream_probes(
    provider_slug: str,
    endpoint_url: str,
    api_key: str,
    claimed_model: str,
) -> dict:
    """
    Execute a real outbound probe battery against the provider's official endpoint:
    - Concurrency capped at 4 workers (gentle personal-plan probing)
    - 14 distribution probes (256-token quota each, reasoning-aware number
      extraction) + 2 tokenizer/cache audit probes = 16 requests total
    - Per-battery hard budget PROBE_TOKEN_BUDGET = 30,000 tokens, enforced
      on real upstream usage as results arrive; exceeding it aborts the
      battery with an error and no report (user ruling 2026-11-06; the
      PRD v1.2 figure of <3,000 tokens per battery is superseded).
    - Requires >= 8 successful completions; otherwise raises ValueError (no fake reports!).
    """
    protocol = ALLOWED_PROVIDERS[provider_slug].get("protocol", "openai")
    # Providers whose gateway requires a session header (declared as
    # "session_header" in ALLOWED_PROVIDERS, e.g. opencode's Go subscription
    # rail) get ONE fresh session id per battery, shared by all 16 calls in
    # the battery and regenerated on the next battery. The id is ephemeral:
    # it is never logged and never persisted.
    session_header = None
    session_header_name = ALLOWED_PROVIDERS[provider_slug].get("session_header")
    if session_header_name:
        session_header = (session_header_name, uuid.uuid4().hex)

    # Budget accounting uses the same usage fields as total_tokens_consumed
    # below (provider-reported prompt + completion tokens; conservative
    # defaults when a failed call carries no usage block).
    def _usage_of(r):
        return r.get("prompt_tokens", 24) + r.get("completion_tokens", 2)

    def _enforce_budget(spent):
        if spent > PROBE_TOKEN_BUDGET:
            raise ValueError(
                f"PROBE_TOKEN_BUDGET_EXCEEDED: 本轮探针真实用量已达 {spent} tokens，"
                f"超过单轮硬顶 {PROBE_TOKEN_BUDGET} tokens（用户 2026-11-06 裁决）；"
                "已中止本轮探测，不生成报告。"
            )

    dist_results = []
    spent_tokens = 0

    try:
        # 1. Run 14 distribution probes with max_workers=4. The 256-token
        # quota lets reasoning models finish thinking AND answer; the
        # extracted number is read from content or reasoning (see
        # extract_number_from_reasoning_or_content).
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            futs = [
                pool.submit(
                    _call_single_upstream_probe,
                    endpoint_url,
                    protocol,
                    api_key,
                    claimed_model,
                    PROBE_PROMPTS_POOL[i % len(PROBE_PROMPTS_POOL)],
                    1.0,
                    256,
                    session_header,
                )
                for i in range(14)
            ]
            for f in concurrent.futures.as_completed(futs):
                r = f.result()
                dist_results.append(r)
                spent_tokens += _usage_of(r)
                _enforce_budget(spent_tokens)

        # 2. Run 2 sequential Tokenizer & Cache Audit probes (turn 1 warms cache, turn 2 measures cache hit)
        audit_r1 = _call_single_upstream_probe(
            endpoint_url, protocol, api_key, claimed_model, TOKENIZER_AUDIT_PROMPT, 0.0, 16,
            session_header=session_header,
        )
        spent_tokens += _usage_of(audit_r1)
        _enforce_budget(spent_tokens)
        audit_r2 = _call_single_upstream_probe(
            endpoint_url, protocol, api_key, claimed_model, TOKENIZER_AUDIT_PROMPT, 0.0, 16,
            session_header=session_header,
        )
        spent_tokens += _usage_of(audit_r2)
        _enforce_budget(spent_tokens)
    finally:
        api_key = None

    all_calls = dist_results + [audit_r1, audit_r2]
    ok_dist = [r for r in dist_results if r.get("ok")]
    count_429 = sum(1 for r in all_calls if r.get("is_429"))
    rate_429_pct = round(100.0 * count_429 / len(all_calls), 1)

    if len(ok_dist) < 8:
        errors = [r.get("error", "ERR") for r in all_calls if not r.get("ok")]
        err_summary = errors[0] if errors else "INSUFFICIENT_SAMPLES"
        raise ValueError(
            f"UPSTREAM_PROBE_FAILED: 真实上游调用未通过（成功 {len(ok_dist)}/14 次，首错: {err_summary}）。"
            "请核对 API Key 有效性、模型权限或上游网络连通性；系统拒绝生成模拟报告。"
        )

    # Tally empirical distribution and odd/even split-half distributions
    counts_all = {k: 0.0 for k in PROBE_BUCKETS}
    counts_half1 = {k: 0.0 for k in PROBE_BUCKETS}
    counts_half2 = {k: 0.0 for k in PROBE_BUCKETS}
    empty_content_count = 0

    for idx, r in enumerate(ok_dist):
        tok = r.get("extracted_token") or ""
        if not tok:
            m = re.search(r"\d+", r.get("text", ""))
            tok = m.group(0) if m else ""
        if not tok:
            empty_content_count += 1
            tok = "other"
        bucket = tok if tok in counts_all else "other"
        counts_all[bucket] += 1.0
        if idx % 2 == 0:
            counts_half1[bucket] += 1.0
        else:
            counts_half2[bucket] += 1.0

    extracted_samples = len(ok_dist) - empty_content_count

    obs_dist = normalize_dist(counts_all)
    split_jsd = compute_jsd(counts_half1, counts_half2)

    # Compute latency & TPS from real responses
    ok_all = [r for r in all_calls if r.get("ok")]
    latencies_ms = sorted(int(r["elapsed_s"] * 1000.0) for r in ok_all)
    ttft_ms = latencies_ms[len(latencies_ms) // 2]
    total_out_tokens = sum(r["completion_tokens"] for r in ok_all)
    total_time_s = max(0.05, sum(r["elapsed_s"] for r in ok_all))
    tps = round(total_out_tokens / total_time_s, 1)

    # Compute Tokenizer & Cache metrics from audit_r1 / audit_r2
    reported_prompt = audit_r2.get("prompt_tokens") or audit_r1.get("prompt_tokens") or EXPECTED_AUDIT_PROMPT_TOKENS
    token_ratio = round(max(0.5, min(3.0, reported_prompt / float(EXPECTED_AUDIT_PROMPT_TOKENS))), 2)
    cached_tok = audit_r2.get("cached_tokens", 0) if audit_r2.get("ok") else 0
    cache_hit_pct = round(min(100.0, 100.0 * cached_tok / max(1, reported_prompt)), 1)
    compression_pct = round(100.0 * reported_prompt / float(EXPECTED_AUDIT_PROMPT_TOKENS), 1)
    total_tokens_consumed = sum((r.get("prompt_tokens", 24) + r.get("completion_tokens", 2)) for r in ok_all)

    return {
        "obs_dist": obs_dist,
        "split_jsd": split_jsd,
        "ttft_ms": ttft_ms,
        "tps": tps,
        "rate_429_pct": rate_429_pct,
        "token_ratio": token_ratio,
        "cache_hit_pct": cache_hit_pct,
        "compression_pct": compression_pct,
        "valid_samples": len(ok_dist),
        "empty_content_count": empty_content_count,
        "extracted_samples": extracted_samples,
        "probe_quality": "insufficient_content_thinking_exhaustion" if extracted_samples < 8 else "normal",
        "total_requests": len(all_calls),
        "total_tokens_consumed": total_tokens_consumed,
    }


INITIAL_PLANS = [
    {
        "provider_slug": "volcengine",
        "plan_slug": "coding-plan-lite",
        "provider_name": "火山引擎方舟",
        "plan_name": "方舟 Coding Plan Lite (¥40/月)",
        "category": "cn_plan",
        "price_label": "¥40/mo (首购 ¥9.9)",
        "claimed_model": "kimi-k3",
        "harness_type": "ark-auto",
        "csl_index_7d": 13.2,
        "csl_iqr": 3.4,
        "net_jsd": 0.148,
        "jsd_std": 0.019,
        "split_jsd": 0.134,
        "tail_ratio": 4.2,
        "nearest_profile": "kimi-k3 (91.4%)",
        "second_profile": "doubao-seed-2.1-turbo (79.8%)",
        "peak_delta_csl": 4.6,
        "token_ratio": 1.01,
        "cache_hit_pct": 91.5,
        "compression_pct": 90.1,
        "median_tps": 84.5,
        "ttft_ms": 480,
        "rate_429_pct": 1.8,
        "sample_count_7d": 519,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "kimi",
        "plan_slug": "kimi-code-pro",
        "provider_name": "Kimi (月之暗面)",
        "plan_name": "Kimi Code Pro (¥199/月 · 5h窗口)",
        "category": "cn_plan",
        "price_label": "¥199/mo",
        "claimed_model": "kimi-k3.1-pro",
        "harness_type": "kimi-cli",
        "csl_index_7d": 10.8,
        "csl_iqr": 2.1,
        "net_jsd": 0.136,
        "jsd_std": 0.014,
        "split_jsd": 0.118,
        "tail_ratio": 2.5,
        "nearest_profile": "kimi-k3.1-pro (94.2%)",
        "second_profile": "kimi-k3 (91.0%)",
        "peak_delta_csl": 2.3,
        "token_ratio": 1.00,
        "cache_hit_pct": 94.8,
        "compression_pct": 90.1,
        "median_tps": 58.2,
        "ttft_ms": 520,
        "rate_429_pct": 2.4,
        "sample_count_7d": 462,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "openai",
        "plan_slug": "payg-official",
        "provider_name": "OpenAI",
        "plan_name": "OpenAI API Pay-as-you-go (个人直连)",
        "category": "payg",
        "price_label": "Pay-as-you-go",
        "claimed_model": "gpt-5.6-sol",
        "harness_type": "raw",
        "csl_index_7d": 8.4,
        "csl_iqr": 1.6,
        "net_jsd": 0.124,
        "jsd_std": 0.011,
        "split_jsd": 0.112,
        "tail_ratio": 1.5,
        "nearest_profile": "gpt-5.6-sol (96.1%)",
        "second_profile": "gpt-6-astra (87.4%)",
        "peak_delta_csl": 1.2,
        "token_ratio": 1.00,
        "cache_hit_pct": 95.2,
        "compression_pct": 100.0,
        "median_tps": 76.0,
        "ttft_ms": 410,
        "rate_429_pct": 0.2,
        "sample_count_7d": 438,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "opencode",
        "plan_slug": "go-10",
        "provider_name": "OpenCode",
        "plan_name": "OpenCode Go ($10/mo · 6x 个人档)",
        "category": "global_coding",
        "price_label": "$10/mo",
        "claimed_model": "kimi-k3.1-pro",
        "harness_type": "opencode",
        "csl_index_7d": 14.6,
        "csl_iqr": 3.8,
        "net_jsd": 0.159,
        "jsd_std": 0.022,
        "split_jsd": 0.141,
        "tail_ratio": 5.0,
        "nearest_profile": "kimi-k3.1-pro (90.8%)",
        "second_profile": "glm-5.3 (76.4%)",
        "peak_delta_csl": 5.4,
        "token_ratio": 1.02,
        "cache_hit_pct": 89.4,
        "compression_pct": 90.1,
        "median_tps": 62.4,
        "ttft_ms": 630,
        "rate_429_pct": 1.9,
        "sample_count_7d": 394,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "commandcode",
        "plan_slug": "goat-10",
        "provider_name": "Command Code",
        "plan_name": "Command Code GOAT ($10/mo · 10x 个人档)",
        "category": "global_coding",
        "price_label": "$10/mo",
        "claimed_model": "deepseek-v4.1-pro",
        "harness_type": "opencode",
        "csl_index_7d": 12.6,
        "csl_iqr": 2.9,
        "net_jsd": 0.148,
        "jsd_std": 0.017,
        "split_jsd": 0.129,
        "tail_ratio": 3.5,
        "nearest_profile": "deepseek-v4.1-pro (94.0%)",
        "second_profile": "deepseek-v4.1-flash (81.2%)",
        "peak_delta_csl": 3.8,
        "token_ratio": 1.00,
        "cache_hit_pct": 97.2,
        "compression_pct": 95.3,
        "median_tps": 68.5,
        "ttft_ms": 540,
        "rate_429_pct": 0.8,
        "sample_count_7d": 356,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "anthropic",
        "plan_slug": "claude-pro-code",
        "provider_name": "Anthropic",
        "plan_name": "Claude Pro ($20/mo · Claude Code 个人档)",
        "category": "global_oa",
        "price_label": "$20/mo",
        "claimed_model": "claude-opus-5.5",
        "harness_type": "claude-code",
        "csl_index_7d": 9.6,
        "csl_iqr": 1.9,
        "net_jsd": 0.131,
        "jsd_std": 0.013,
        "split_jsd": 0.116,
        "tail_ratio": 2.0,
        "nearest_profile": "claude-opus-5.5 (95.4%)",
        "second_profile": "claude-sonnet-5 (88.1%)",
        "peak_delta_csl": 2.1,
        "token_ratio": 1.01,
        "cache_hit_pct": 96.0,
        "compression_pct": 165.6,
        "median_tps": 54.0,
        "ttft_ms": 590,
        "rate_429_pct": 3.2,
        "sample_count_7d": 341,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "zhipu",
        "plan_slug": "glm-coding-lite",
        "provider_name": "智谱清言 (Z.ai)",
        "plan_name": "GLM Coding Plan Lite (¥118/月 · 5h积分)",
        "category": "cn_plan",
        "price_label": "¥118/mo",
        "claimed_model": "glm-5.3",
        "harness_type": "claude-code",
        "csl_index_7d": 15.8,
        "csl_iqr": 4.2,
        "net_jsd": 0.165,
        "jsd_std": 0.024,
        "split_jsd": 0.149,
        "tail_ratio": 6.5,
        "nearest_profile": "glm-5.3 (89.6%)",
        "second_profile": "deepseek-v4.1-flash (74.2%)",
        "peak_delta_csl": 6.8,
        "token_ratio": 1.03,
        "cache_hit_pct": 88.5,
        "compression_pct": 95.7,
        "median_tps": 42.8,
        "ttft_ms": 710,
        "rate_429_pct": 5.6,
        "sample_count_7d": 312,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "cursor",
        "plan_slug": "pro-20",
        "provider_name": "Cursor",
        "plan_name": "Cursor Pro ($20/mo 个人档 · Auto/Sonnet)",
        "category": "global_coding",
        "price_label": "$20/mo",
        "claimed_model": "claude-sonnet-5",
        "harness_type": "cursor",
        "csl_index_7d": 18.4,
        "csl_iqr": 5.1,
        "net_jsd": 0.178,
        "jsd_std": 0.028,
        "split_jsd": 0.162,
        "tail_ratio": 8.0,
        "nearest_profile": "claude-sonnet-5 (86.5%)",
        "second_profile": "grok-4.7 (78.2%)",
        "peak_delta_csl": 7.2,
        "token_ratio": 1.08,
        "cache_hit_pct": 92.1,
        "compression_pct": 165.9,
        "median_tps": 71.3,
        "ttft_ms": 490,
        "rate_429_pct": 1.1,
        "sample_count_7d": 289,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "minimax",
        "plan_slug": "token-plan-plus",
        "provider_name": "MiniMax",
        "plan_name": "MiniMax Token Plan Plus (¥49/月 · 6亿Token)",
        "category": "cn_plan",
        "price_label": "¥49/mo",
        "claimed_model": "minimax-m3",
        "harness_type": "raw",
        "csl_index_7d": 11.4,
        "csl_iqr": 2.3,
        "net_jsd": 0.141,
        "jsd_std": 0.015,
        "split_jsd": 0.122,
        "tail_ratio": 3.0,
        "nearest_profile": "minimax-m3 (93.8%)",
        "second_profile": "kimi-k3 (75.1%)",
        "peak_delta_csl": 2.5,
        "token_ratio": 1.00,
        "cache_hit_pct": 93.4,
        "compression_pct": 90.5,
        "median_tps": 96.4,
        "ttft_ms": 380,
        "rate_429_pct": 0.9,
        "sample_count_7d": 267,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "bailian",
        "plan_slug": "token-plan-lite",
        "provider_name": "阿里云百炼",
        "plan_name": "百炼 Token Plan Lite (¥39/月 · 11.5K Credits)",
        "category": "cn_plan",
        "price_label": "¥39/mo",
        "claimed_model": "qwen3.8-max",
        "harness_type": "raw",
        "csl_index_7d": 12.1,
        "csl_iqr": 2.6,
        "net_jsd": 0.144,
        "jsd_std": 0.016,
        "split_jsd": 0.126,
        "tail_ratio": 3.2,
        "nearest_profile": "qwen3.8-max (93.2%)",
        "second_profile": "glm-5.3 (76.0%)",
        "peak_delta_csl": 2.9,
        "token_ratio": 1.01,
        "cache_hit_pct": 90.8,
        "compression_pct": 95.4,
        "median_tps": 63.7,
        "ttft_ms": 460,
        "rate_429_pct": 1.4,
        "sample_count_7d": 243,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "xai",
        "plan_slug": "grok-payg",
        "provider_name": "xAI (Grok)",
        "plan_name": "xAI API Pay-as-you-go / X Premium 个人档",
        "category": "global_oa",
        "price_label": "Pay-as-you-go / $30",
        "claimed_model": "grok-4.7",
        "harness_type": "raw",
        "csl_index_7d": 9.1,
        "csl_iqr": 1.8,
        "net_jsd": 0.128,
        "jsd_std": 0.012,
        "split_jsd": 0.115,
        "tail_ratio": 1.8,
        "nearest_profile": "grok-4.7 (95.6%)",
        "second_profile": "gpt-5.6-sol (78.4%)",
        "peak_delta_csl": 1.6,
        "token_ratio": 1.00,
        "cache_hit_pct": 94.1,
        "compression_pct": 94.4,
        "median_tps": 88.2,
        "ttft_ms": 390,
        "rate_429_pct": 0.4,
        "sample_count_7d": 218,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "kiro",
        "plan_slug": "pro-20",
        "provider_name": "Kiro (AWS Spec IDE)",
        "plan_name": "Kiro Pro ($20/mo · 1,000 Credits 个人自服务档)",
        "category": "global_coding",
        "price_label": "$20/mo",
        "claimed_model": "claude-sonnet-5",
        "harness_type": "kiro",
        "csl_index_7d": 16.2,
        "csl_iqr": 4.0,
        "net_jsd": 0.168,
        "jsd_std": 0.021,
        "split_jsd": 0.151,
        "tail_ratio": 6.0,
        "nearest_profile": "claude-sonnet-5 (88.9%)",
        "second_profile": "claude-haiku-4.5 (79.5%)",
        "peak_delta_csl": 4.9,
        "token_ratio": 1.04,
        "cache_hit_pct": 90.2,
        "compression_pct": 165.9,
        "median_tps": 59.5,
        "ttft_ms": 560,
        "rate_429_pct": 1.5,
        "sample_count_7d": 195,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "kilo",
        "plan_slug": "pass-starter",
        "provider_name": "Kilo Code",
        "plan_name": "Kilo Pass Starter ($19/mo · 个人 Gateway)",
        "category": "global_coding",
        "price_label": "$19/mo",
        "claimed_model": "claude-sonnet-5",
        "harness_type": "raw",
        "csl_index_7d": 13.8,
        "csl_iqr": 3.1,
        "net_jsd": 0.153,
        "jsd_std": 0.018,
        "split_jsd": 0.135,
        "tail_ratio": 4.0,
        "nearest_profile": "claude-sonnet-5 (91.8%)",
        "second_profile": "claude-opus-5.5 (84.2%)",
        "peak_delta_csl": 3.3,
        "token_ratio": 1.01,
        "cache_hit_pct": 91.0,
        "compression_pct": 165.9,
        "median_tps": 61.0,
        "ttft_ms": 530,
        "rate_429_pct": 1.2,
        "sample_count_7d": 176,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "xiaomi",
        "plan_slug": "mimo-token-lite",
        "provider_name": "小米 MiMo",
        "plan_name": "MiMo Token Plan Lite (¥39/月 · 无周/5h限额)",
        "category": "cn_plan",
        "price_label": "¥39/mo",
        "claimed_model": "mimo-v2.6-pro",
        "harness_type": "raw",
        "csl_index_7d": 11.9,
        "csl_iqr": 2.4,
        "net_jsd": 0.143,
        "jsd_std": 0.015,
        "split_jsd": 0.125,
        "tail_ratio": 2.8,
        "nearest_profile": "mimo-v2.6-pro (93.5%)",
        "second_profile": "qwen3.8-max (77.4%)",
        "peak_delta_csl": 2.2,
        "token_ratio": 1.00,
        "cache_hit_pct": 92.6,
        "compression_pct": 101.2,
        "median_tps": 52.4,
        "ttft_ms": 495,
        "rate_429_pct": 0.7,
        "sample_count_7d": 164,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
    {
        "provider_slug": "copilot",
        "plan_slug": "pro-10",
        "provider_name": "GitHub Copilot",
        "plan_name": "GitHub Copilot Pro ($10/mo · 个人档)",
        "category": "global_coding",
        "price_label": "$10/mo",
        "claimed_model": "gpt-5.6-sol",
        "harness_type": "cursor",
        "csl_index_7d": 14.9,
        "csl_iqr": 3.5,
        "net_jsd": 0.161,
        "jsd_std": 0.020,
        "split_jsd": 0.142,
        "tail_ratio": 4.8,
        "nearest_profile": "gpt-5.6-sol (90.4%)",
        "second_profile": "gpt-5.6-luna (82.1%)",
        "peak_delta_csl": 4.1,
        "token_ratio": 1.03,
        "cache_hit_pct": 90.5,
        "compression_pct": 100.0,
        "median_tps": 69.8,
        "ttft_ms": 450,
        "rate_429_pct": 1.0,
        "sample_count_7d": 152,
        "verified_sample_count": 0,
        "data_origin": "Simulated-Demo",
    },
]


class CSLDatabase:
    """Single-file SQLite WAL time-series store with strict Demo vs Server-Verified isolation."""

    # Columns added after the v1 schema shipped. CREATE TABLE IF NOT EXISTS
    # never alters an existing table, so databases created by v1 code lack
    # these; _migrate_columns adds whichever are absent at startup. The
    # declarations must match the CREATE TABLE definitions below exactly;
    # the defaults stamp pre-existing rows as demo data, which is what
    # anything written by v1 code is.
    _COLUMN_MIGRATIONS = {
        "plans": (
            ("verified_sample_count", "INTEGER NOT NULL DEFAULT 0"),
            ("data_origin", "TEXT NOT NULL DEFAULT 'Simulated-Demo'"),
        ),
        "reports": (
            ("data_origin", "TEXT NOT NULL DEFAULT 'Simulated-Demo'"),
        ),
        "timeline_series": (
            ("data_origin", "TEXT NOT NULL DEFAULT 'Simulated-Demo'"),
        ),
    }

    def __init__(self, db_path: str):
        self.db_path = os.path.abspath(db_path)
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._lock = threading.Lock()
        self._runtime_path = self._resolve_runtime_path()
        self._init_schema()
        self._sync_snapshot()

    def _resolve_runtime_path(self) -> str:
        try:
            c = sqlite3.connect(self.db_path, timeout=2.0)
            c.execute("CREATE TABLE IF NOT EXISTS _probe_fs (id INT);")
            c.commit()
            c.close()
            return self.db_path
        except sqlite3.OperationalError:
            h = hashlib.sha256(self.db_path.encode()).hexdigest()[:12]
            rt = f"/tmp/csl_meter_{h}.db"
            if os.path.exists(self.db_path) and os.path.getsize(self.db_path) > 0 and not os.path.exists(rt):
                shutil.copyfile(self.db_path, rt)
            return rt

    def _sync_snapshot(self):
        if self._runtime_path != self.db_path and os.path.exists(self._runtime_path):
            conn = sqlite3.connect(self._runtime_path)
            conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
            conn.close()
            shutil.copyfile(self._runtime_path, self.db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._runtime_path, timeout=10.0, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        conn.execute("PRAGMA temp_store=MEMORY;")
        return conn

    def _init_schema(self):
        with self._lock:
            conn = self._connect()
            try:
                conn.executescript(
                    """
                    CREATE TABLE IF NOT EXISTS plans (
                        provider_slug TEXT NOT NULL,
                        plan_slug TEXT NOT NULL,
                        provider_name TEXT NOT NULL,
                        plan_name TEXT NOT NULL,
                        category TEXT NOT NULL,
                        price_label TEXT NOT NULL,
                        claimed_model TEXT NOT NULL,
                        harness_type TEXT NOT NULL,
                        csl_index_7d REAL NOT NULL,
                        csl_iqr REAL NOT NULL,
                        net_jsd REAL NOT NULL,
                        jsd_std REAL NOT NULL,
                        split_jsd REAL NOT NULL,
                        tail_ratio REAL NOT NULL,
                        nearest_profile TEXT NOT NULL,
                        second_profile TEXT NOT NULL,
                        peak_delta_csl REAL NOT NULL,
                        token_ratio REAL NOT NULL,
                        cache_hit_pct REAL NOT NULL,
                        compression_pct REAL NOT NULL,
                        median_tps REAL NOT NULL,
                        ttft_ms INTEGER NOT NULL,
                        rate_429_pct REAL NOT NULL,
                        sample_count_7d INTEGER NOT NULL,
                        verified_sample_count INTEGER NOT NULL DEFAULT 0,
                        data_origin TEXT NOT NULL DEFAULT 'Simulated-Demo',
                        updated_at TEXT NOT NULL,
                        PRIMARY KEY (provider_slug, plan_slug)
                    );

                    CREATE TABLE IF NOT EXISTS reports (
                        uuid TEXT PRIMARY KEY,
                        created_at TEXT NOT NULL,
                        provider_slug TEXT NOT NULL,
                        plan_slug TEXT NOT NULL,
                        provider_name TEXT NOT NULL,
                        plan_name TEXT NOT NULL,
                        claimed_model TEXT NOT NULL,
                        harness_type TEXT NOT NULL,
                        quota_window_stage TEXT NOT NULL,
                        verification_mode TEXT NOT NULL,
                        data_origin TEXT NOT NULL DEFAULT 'Simulated-Demo',
                        key_dedup_hash TEXT NOT NULL,
                        csl_index REAL NOT NULL,
                        raw_jsd REAL NOT NULL,
                        net_jsd REAL NOT NULL,
                        split_jsd REAL NOT NULL,
                        tail_ratio REAL NOT NULL,
                        nearest_profile TEXT NOT NULL,
                        second_profile TEXT NOT NULL,
                        token_ratio REAL NOT NULL,
                        cache_hit_pct REAL NOT NULL,
                        compression_pct REAL NOT NULL,
                        tps REAL NOT NULL,
                        ttft_ms INTEGER NOT NULL,
                        rate_429_pct REAL NOT NULL,
                        observed_dist_json TEXT NOT NULL,
                        baseline_dist_json TEXT NOT NULL,
                        nearest_ranking_json TEXT NOT NULL
                    );

                    CREATE TABLE IF NOT EXISTS timeline_series (
                        provider_slug TEXT NOT NULL,
                        plan_slug TEXT NOT NULL,
                        bucket_type TEXT NOT NULL,
                        bucket_label TEXT NOT NULL,
                        seq_order INTEGER NOT NULL,
                        csl_index REAL NOT NULL,
                        net_jsd REAL NOT NULL,
                        tps REAL NOT NULL,
                        rate_429_pct REAL NOT NULL,
                        sample_count INTEGER NOT NULL,
                        data_origin TEXT NOT NULL DEFAULT 'Simulated-Demo',
                        PRIMARY KEY (provider_slug, plan_slug, bucket_type, bucket_label)
                    );
                    """
                )
                self._migrate_columns(conn)
                cur = conn.execute("SELECT COUNT(*) AS cnt FROM plans")
                if cur.fetchone()["cnt"] == 0:
                    self._seed_initial_data(conn)
                conn.commit()
            finally:
                conn.close()

    def _migrate_columns(self, conn: sqlite3.Connection):
        """Add post-v1 columns to pre-existing tables; no-op when present.

        Idempotent: safe on every startup, including databases created by
        current code (all columns already there) and repeated opens.
        """
        for table, columns in self._COLUMN_MIGRATIONS.items():
            existing = {
                row["name"] for row in conn.execute(f"PRAGMA table_info({table})")
            }
            for name, decl in columns:
                if name not in existing:
                    conn.execute(f"ALTER TABLE {table} ADD COLUMN {name} {decl}")

    def _seed_initial_data(self, conn: sqlite3.Connection):
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rng = random.Random(20261105)
        for p in INITIAL_PLANS:
            conn.execute(
                """
                INSERT INTO plans (
                    provider_slug, plan_slug, provider_name, plan_name, category,
                    price_label, claimed_model, harness_type, csl_index_7d, csl_iqr,
                    net_jsd, jsd_std, split_jsd, tail_ratio, nearest_profile,
                    second_profile, peak_delta_csl, token_ratio, cache_hit_pct,
                    compression_pct, median_tps, ttft_ms, rate_429_pct,
                    sample_count_7d, verified_sample_count, data_origin, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    p["provider_slug"], p["plan_slug"], p["provider_name"], p["plan_name"],
                    p["category"], p["price_label"], p["claimed_model"], p["harness_type"],
                    p["csl_index_7d"], p["csl_iqr"], p["net_jsd"], p["jsd_std"],
                    p["split_jsd"], p["tail_ratio"], p["nearest_profile"], p["second_profile"],
                    p["peak_delta_csl"], p["token_ratio"], p["cache_hit_pct"],
                    p["compression_pct"], p["median_tps"], p["ttft_ms"], p["rate_429_pct"],
                    p["sample_count_7d"], 0, "Simulated-Demo", now_iso,
                ),
            )
            for h in range(24):
                is_peak = 14 <= h <= 18 or 21 <= h <= 23
                delta = p["peak_delta_csl"] * (0.85 + 0.3 * rng.random()) if is_peak else -0.8 * rng.random()
                h_csl = round(max(4.0, p["csl_index_7d"] + delta), 1)
                h_jsd = round(max(0.105, p["net_jsd"] + (delta * 0.004)), 3)
                h_tps = round(max(18.0, p["median_tps"] * (0.78 if is_peak else 1.05) + rng.uniform(-3.0, 3.0)), 1)
                h_429 = round(max(0.0, p["rate_429_pct"] * (1.7 if is_peak else 0.4)), 1)
                conn.execute(
                    "INSERT INTO timeline_series (provider_slug, plan_slug, bucket_type, bucket_label, seq_order, csl_index, net_jsd, tps, rate_429_pct, sample_count, data_origin) VALUES (?, ?, 'hourly_24h', ?, ?, ?, ?, ?, ?, ?, 'Simulated-Demo')",
                    (p["provider_slug"], p["plan_slug"], f"{h:02d}:00", h, h_csl, h_jsd, h_tps, h_429, max(4, int(p["sample_count_7d"] / 24))),
                )
            for d in range(30):
                day_label = f"10-{d+7:02d}" if d < 25 else f"11-{d-24:02d}"
                drift = rng.uniform(-1.8, 2.2)
                d_csl = round(max(4.5, p["csl_index_7d"] + drift), 1)
                d_jsd = round(max(0.110, p["net_jsd"] + drift * 0.003), 3)
                d_tps = round(max(20.0, p["median_tps"] + rng.uniform(-5.0, 5.0)), 1)
                d_429 = round(max(0.0, p["rate_429_pct"] + rng.uniform(-0.5, 0.8)), 1)
                conn.execute(
                    "INSERT INTO timeline_series (provider_slug, plan_slug, bucket_type, bucket_label, seq_order, csl_index, net_jsd, tps, rate_429_pct, sample_count, data_origin) VALUES (?, ?, 'daily_30d', ?, ?, ?, ?, ?, ?, ?, 'Simulated-Demo')",
                    (p["provider_slug"], p["plan_slug"], day_label, d, d_csl, d_jsd, d_tps, d_429, max(5, int(p["sample_count_7d"] / 7))),
                )

        # Seed 3 demo reports explicitly marked 'Simulated · 模拟生成' (never 'Server-Verified')
        demo_specs = [
            ("a49d2e", "commandcode", "goat-10", "window_early (<30%)"),
            ("8f3a9c", "volcengine", "coding-plan-lite", "window_late (>70%)"),
            ("c71b04", "openai", "payg-official", "window_early (<30%)"),
        ]
        for rep_id, prov_slug, pl_slug, stage in demo_specs:
            plan_meta = next(x for x in INITIAL_PLANS if x["provider_slug"] == prov_slug and x["plan_slug"] == pl_slug)
            claimed = plan_meta["claimed_model"]
            base_dist = GOLDEN_BASELINES[claimed]["dist"]
            bias = HARNESS_BIAS_VECTORS.get(plan_meta["harness_type"], HARNESS_BIAS_VECTORS["raw"])
            obs_dist = normalize_dist({k: base_dist[k] + bias.get(k, 0.0) + rng.uniform(-0.012, 0.012) for k in PROBE_BUCKETS})
            net_dist = de_bias_harness_dist(obs_dist, plan_meta["harness_type"])
            ranked = find_nearest_profiles(net_dist)
            conn.execute(
                """
                INSERT INTO reports (
                    uuid, created_at, provider_slug, plan_slug, provider_name,
                    plan_name, claimed_model, harness_type, quota_window_stage,
                    verification_mode, data_origin, key_dedup_hash, csl_index,
                    raw_jsd, net_jsd, split_jsd, tail_ratio, nearest_profile,
                    second_profile, token_ratio, cache_hit_pct, compression_pct,
                    tps, ttft_ms, rate_429_pct, observed_dist_json,
                    baseline_dist_json, nearest_ranking_json
                ) VALUES (
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Simulated · 模拟生成', 'Simulated-Demo', ?,
                    ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                )
                """,
                (
                    rep_id, now_iso, prov_slug, pl_slug,
                    plan_meta["provider_name"], plan_meta["plan_name"],
                    claimed, plan_meta["harness_type"], stage, "demo-seed-" + rep_id,
                    plan_meta["csl_index_7d"], round(plan_meta["net_jsd"] + 0.024, 4),
                    plan_meta["net_jsd"], plan_meta["split_jsd"], plan_meta["tail_ratio"],
                    f"{ranked[0]['model']} ({ranked[0]['similarity']}%)",
                    f"{ranked[1]['model']} ({ranked[1]['similarity']}%)",
                    plan_meta["token_ratio"], plan_meta["cache_hit_pct"], plan_meta["compression_pct"],
                    plan_meta["median_tps"], plan_meta["ttft_ms"], plan_meta["rate_429_pct"],
                    json.dumps(obs_dist), json.dumps(base_dist), json.dumps(ranked[:5]),
                ),
            )

    def list_plans(self, category: str = None, sort_by: str = "sample_count_7d", order: str = "desc", only_verified: bool = False) -> list:
        valid_cols = {
            "sample_count_7d", "verified_sample_count", "csl_index_7d", "net_jsd",
            "split_jsd", "peak_delta_csl", "token_ratio", "cache_hit_pct",
            "median_tps", "ttft_ms", "rate_429_pct", "plan_name", "provider_name"
        }
        col = sort_by if sort_by in valid_cols else "sample_count_7d"
        direction = "ASC" if str(order).lower() == "asc" else "DESC"
        conn = self._connect()
        try:
            clauses = []
            params = []
            if category and category != "all":
                clauses.append("category = ?")
                params.append(category)
            if only_verified:
                clauses.append("verified_sample_count > 0")
            where_sql = ("WHERE " + " AND ".join(clauses)) if clauses else ""
            cur = conn.execute(f"SELECT * FROM plans {where_sql} ORDER BY {col} {direction}", tuple(params))
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def get_plan(self, provider_slug: str, plan_slug: str) -> dict:
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT * FROM plans WHERE provider_slug = ? AND plan_slug = ?",
                (provider_slug, plan_slug),
            )
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_report(self, report_uuid: str) -> dict:
        conn = self._connect()
        try:
            cur = conn.execute("SELECT * FROM reports WHERE uuid = ?", (report_uuid,))
            row = cur.fetchone()
            if not row:
                return None
            d = dict(row)
            d["observed_dist"] = json.loads(d["observed_dist_json"])
            d["baseline_dist"] = json.loads(d["baseline_dist_json"])
            d["nearest_ranking"] = json.loads(d["nearest_ranking_json"])
            return d
        finally:
            conn.close()

    def list_recent_reports(self, limit: int = 12, only_verified: bool = False) -> list:
        conn = self._connect()
        try:
            where_sql = "WHERE data_origin = 'Server-Verified'" if only_verified else ""
            cur = conn.execute(
                f"SELECT uuid, created_at, provider_slug, plan_slug, provider_name, plan_name, claimed_model, quota_window_stage, verification_mode, data_origin, csl_index, net_jsd, split_jsd, nearest_profile, token_ratio, tps, ttft_ms FROM reports {where_sql} ORDER BY created_at DESC LIMIT ?",
                (limit,),
            )
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def get_timeline(self, provider_slug: str, plan_slug: str, bucket_type: str = "hourly_24h") -> list:
        conn = self._connect()
        try:
            cur = conn.execute(
                "SELECT * FROM timeline_series WHERE provider_slug = ? AND plan_slug = ? AND bucket_type = ? ORDER BY seq_order ASC",
                (provider_slug, plan_slug, bucket_type),
            )
            return [dict(r) for r in cur.fetchall()]
        finally:
            conn.close()

    def count_verified_reports(self) -> int:
        conn = self._connect()
        try:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM reports WHERE data_origin = 'Server-Verified'")
            return int(cur.fetchone()["cnt"])
        finally:
            conn.close()

    def count_plans(self) -> int:
        conn = self._connect()
        try:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM plans")
            return int(cur.fetchone()["cnt"])
        finally:
            conn.close()

    def count_verified_plans(self) -> int:
        """Plans whose aggregate row has flipped to Server-Verified, i.e. plans
        carrying at least one real probe sample (see record_probe_submission).
        Added for the strict site-wide data_status rule in app.py."""
        conn = self._connect()
        try:
            cur = conn.execute("SELECT COUNT(*) AS cnt FROM plans WHERE data_origin = 'Server-Verified'")
            return int(cur.fetchone()["cnt"])
        finally:
            conn.close()

    def record_probe_submission(self, payload: dict) -> dict:
        """
        Execute a REAL outbound probe battery using the submitted temporary credential,
        wipe the credential from memory in finally, and persist the verified report.
        Synthetic/fake keys fail the real HTTP call and never enter the database.
        """
        provider_slug = str(payload.get("provider_slug", "")).strip()
        plan_slug = str(payload.get("plan_slug", "")).strip()
        quota_stage = str(payload.get("quota_window_stage", "window_early (<30%)")).strip()
        custom_url = payload.get("base_url") or payload.get("custom_url") or None

        # 1. Strict SSRF Whitelist Check
        ok, endpoint_or_err = validate_ssrf_whitelist(provider_slug, custom_url)
        if not ok:
            raise ValueError(endpoint_or_err)

        plan = self.get_plan(provider_slug, plan_slug)
        if not plan:
            raise ValueError(f"PLAN_NOT_FOUND: 未找到套餐 '{provider_slug}/{plan_slug}'。")

        claimed_model = str(payload.get("claimed_model") or plan["claimed_model"]).strip()
        if claimed_model not in GOLDEN_BASELINES:
            claimed_model = plan["claimed_model"]
        harness_type = str(payload.get("harness_type") or plan["harness_type"]).strip()

        # 2. Extract API key in local stack frame, execute real outbound HTTP probes, and wipe in finally
        api_key = str(payload.get("api_key", "")).strip()
        try:
            if not api_key or len(api_key) < 6:
                raise ValueError("INVALID_CREDENTIAL: 请输入有效的临时测试凭证（长度至少 6 位）。")
            key_dedup_hash = compute_irreversible_key_hash(api_key)
            live_telemetry = execute_real_upstream_probes(
                provider_slug=provider_slug,
                endpoint_url=endpoint_or_err,
                api_key=api_key,
                claimed_model=claimed_model,
            )
        finally:
            api_key = None
            if "api_key" in payload:
                payload["api_key"] = None

        # 3. Ruling (user, 2026-11-06): the probe_quality / empty-content
        # counts must have a real consumer. If fewer than 8 of the
        # distribution samples yielded an extractable number — the rest had
        # empty content because reasoning exhausted the response — the
        # battery observed nothing identifiable, so NO report is filed and
        # the plan aggregate is left untouched (same bar as the >= 8
        # successful-completions gate in the battery itself).
        extracted_samples = live_telemetry["extracted_samples"]
        if extracted_samples < 8:
            raise ValueError(
                "INSUFFICIENT_PROBE_CONTENT: 探针样本不足——"
                f"分布采样中仅 {extracted_samples} 次提取到数字"
                "（其余响应正文为空、推理耗尽或思考未产出结论），"
                "无法形成可信识别结论；系统拒绝生成报告。"
            )

        obs_dist = live_telemetry["obs_dist"]
        base_dist = GOLDEN_BASELINES[claimed_model]["dist"]
        raw_jsd = compute_jsd(obs_dist, base_dist)
        net_dist = de_bias_harness_dist(obs_dist, harness_type)
        net_jsd = compute_jsd(net_dist, base_dist)
        split_jsd = live_telemetry["split_jsd"]
        tail_ratio = round(min(25.0, max(0.5, (split_jsd - 0.06) * 60.0)), 1)
        token_ratio = live_telemetry["token_ratio"]
        csl_index = compute_csl_index(net_jsd, split_jsd, token_ratio)
        ranked = find_nearest_profiles(net_dist)

        rep_uuid = uuid.uuid4().hex[:8]
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        with self._lock:
            conn = self._connect()
            try:
                conn.execute(
                    """
                    INSERT INTO reports (
                        uuid, created_at, provider_slug, plan_slug, provider_name,
                        plan_name, claimed_model, harness_type, quota_window_stage,
                        verification_mode, data_origin, key_dedup_hash, csl_index,
                        raw_jsd, net_jsd, split_jsd, tail_ratio, nearest_profile,
                        second_profile, token_ratio, cache_hit_pct, compression_pct,
                        tps, ttft_ms, rate_429_pct, observed_dist_json,
                        baseline_dist_json, nearest_ranking_json
                    ) VALUES (
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, 'Server-Verified', 'Server-Verified', ?,
                        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                    )
                    """,
                    (
                        rep_uuid, now_iso, provider_slug, plan_slug,
                        plan["provider_name"], plan["plan_name"],
                        claimed_model, harness_type, quota_stage, key_dedup_hash,
                        csl_index, raw_jsd, net_jsd, split_jsd, tail_ratio,
                        f"{ranked[0]['model']} ({ranked[0]['similarity']}%)",
                        f"{ranked[1]['model']} ({ranked[1]['similarity']}%)",
                        token_ratio, live_telemetry["cache_hit_pct"], live_telemetry["compression_pct"],
                        live_telemetry["tps"], live_telemetry["ttft_ms"], live_telemetry["rate_429_pct"],
                        json.dumps(obs_dist), json.dumps(base_dist), json.dumps(ranked[:5]),
                    ),
                )
                # Once a plan receives real Server-Verified data, transition its aggregate row to Server-Verified
                prev_v = int(plan.get("verified_sample_count", 0))
                if prev_v == 0:
                    # Replace demo baseline numbers with the first real verified measurement
                    new_v = 1
                    new_n = 1
                    new_csl = csl_index
                    new_jsd = net_jsd
                    new_split = split_jsd
                    new_tps = live_telemetry["tps"]
                    new_ttft = live_telemetry["ttft_ms"]
                    new_429 = live_telemetry["rate_429_pct"]
                else:
                    new_v = prev_v + 1
                    new_n = prev_v + 1
                    new_csl = round((plan["csl_index_7d"] * prev_v + csl_index) / new_v, 1)
                    new_jsd = round((plan["net_jsd"] * prev_v + net_jsd) / new_v, 3)
                    new_split = round((plan["split_jsd"] * prev_v + split_jsd) / new_v, 3)
                    new_tps = round((plan["median_tps"] * prev_v + live_telemetry["tps"]) / new_v, 1)
                    new_ttft = int((plan["ttft_ms"] * prev_v + live_telemetry["ttft_ms"]) / new_v)
                    new_429 = round((plan["rate_429_pct"] * prev_v + live_telemetry["rate_429_pct"]) / new_v, 1)

                conn.execute(
                    """
                    UPDATE plans
                    SET sample_count_7d = ?, verified_sample_count = ?, data_origin = 'Server-Verified',
                        csl_index_7d = ?, net_jsd = ?, split_jsd = ?, median_tps = ?, ttft_ms = ?,
                        rate_429_pct = ?, nearest_profile = ?, second_profile = ?, updated_at = ?
                    WHERE provider_slug = ? AND plan_slug = ?
                    """,
                    (
                        new_n, new_v, new_csl, new_jsd, new_split, new_tps, new_ttft, new_429,
                        f"{ranked[0]['model']} ({ranked[0]['similarity']}%)",
                        f"{ranked[1]['model']} ({ranked[1]['similarity']}%)",
                        now_iso, provider_slug, plan_slug,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
            self._sync_snapshot()

        return self.get_report(rep_uuid)


def render_svg_badge(target_label: str, csl_val: float, jsd_val: float, tps_val: float, n_val: int, is_demo: bool = True) -> str:
    """
    Generate cold-dark-slate + electric-blue SVG badge.
    Appends ' · DEMO' suffix whenever data_origin is Simulated-Demo, and removes it once Server-Verified.
    """
    left_text = "⚡ CSL-Meter"
    mid_text = target_label[:28]
    suffix = " · DEMO" if is_demo else ""
    right_text = f"CSL {csl_val:.1f} · JSD {jsd_val:.3f} · {tps_val:.0f} TPS · N={n_val}{suffix}"

    w_left = 98
    w_mid = max(120, len(mid_text) * 7 + 18)
    w_right = max(225, len(right_text) * 6.8 + 18)
    total_w = int(w_left + w_mid + w_right)

    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="24" viewBox="0 0 {total_w} 24" role="img" aria-label="{left_text}: {mid_text} {right_text}">
  <title>{left_text} | {mid_text} | {right_text} (konspace.cc)</title>
  <defs>
    <linearGradient id="bg-left" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0%" stop-color="#0F172A"/>
      <stop offset="100%" stop-color="#0B0F17"/>
    </linearGradient>
    <linearGradient id="bg-right" x1="0" y1="0" x2="1" y2="0">
      <stop offset="0%" stop-color="#0369A1"/>
      <stop offset="100%" stop-color="#0284C7"/>
    </linearGradient>
  </defs>
  <rect width="{total_w}" height="24" rx="4" fill="#161F30" stroke="#1E293B" stroke-width="1"/>
  <path d="M4 0 H{w_left} V24 H4 A4 4 0 0 1 0 20 V4 A4 4 0 0 1 4 0 Z" fill="url(#bg-left)"/>
  <path d="M{w_left + w_mid} 0 H{total_w - 4} A4 4 0 0 1 {total_w} 4 V20 A4 4 0 0 1 {total_w - 4} 24 H{w_left + w_mid} Z" fill="url(#bg-right)"/>
  <line x1="{w_left}" y1="0" x2="{w_left}" y2="24" stroke="#1E293B" stroke-width="1"/>
  <line x1="{w_left + w_mid}" y1="0" x2="{w_left + w_mid}" y2="24" stroke="#0EA5E9" stroke-width="1"/>
  <g font-family="'JetBrains Mono', 'IBM Plex Mono', ui-monospace, SFMono-Regular, monospace" font-size="11" font-variant-numeric="tabular-nums">
    <text x="{w_left / 2:.1f}" y="15.5" fill="#38BDF8" font-weight="700" text-anchor="middle">{left_text}</text>
    <text x="{w_left + w_mid / 2:.1f}" y="15.5" fill="#E2E8F0" font-weight="500" text-anchor="middle">{mid_text}</text>
    <text x="{w_left + w_mid + w_right / 2:.1f}" y="15.5" fill="#F8FAFC" font-weight="600" text-anchor="middle">{right_text}</text>
  </g>
</svg>"""
