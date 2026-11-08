#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CSL-Meter Web & API Server (https://konspace.cc | https://api.konspace.cc)
Real outbound probe engine with data_origin demo/verified isolation and
Cloudflare Turnstile widget + siteverify enforcement, behind an optional
overlay access gate with a site-wide restricted-demo banner.
"""

import hashlib
import html
import hmac
import json
import os
import re
import secrets
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from csl_engine import (
    ALLOWED_PROVIDERS,
    API_DOMAIN,
    BRAND_FULL,
    BRAND_NAME,
    CSLDatabase,
    GOLDEN_BASELINES,
    INITIAL_PLANS,
    PROBE_BUCKETS,
    SITE_DOMAIN,
    render_svg_badge,
)

DB_PATH = os.environ.get(
    "CSL_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "csl_meter.db"),
)

_TEST_TURNSTILE_VERIFY_URL = None

# ---------------------------------------------------------------------------
# Access overlay:
# 1) DATA LABELING - every rendered surface carries the public-data
#    banner below. The probe engine is real;
#    per-plan/per-report demo-vs-verified labeling is governed by the
#    engine's data_origin system (Simulated-Demo vs Server-Verified), and
#    this overlay no longer rewrites labels site-wide.
# 2) ACCESS GATE - removed site-wide in v1.5.0: every route is public.
#    The login machinery below is retained for self-hosted deployments
#    that set CSL_GATE_PASSWORD_SHA256, but no route requires it.
#    The probe submission endpoint keeps its Cloudflare Turnstile check
#    (anti-abuse, not authentication).
# ---------------------------------------------------------------------------
GATE_USER = os.environ.get("CSL_GATE_USER", "admin")
GATE_PASSWORD_SHA256 = os.environ.get("CSL_GATE_PASSWORD_SHA256", "").strip().lower()
GATE_ENABLED = bool(GATE_PASSWORD_SHA256)
SESSION_TTL_SECONDS = 12 * 3600
_sessions = {}
_sessions_lock = threading.Lock()

DEMO_NOTICE_ZH = "本站数据全部公开：标注 Simulated · 模拟生成 的是模拟基线数据，标注 Server-Verified 的是真实探测记录，请按标注区分；黄金基线校准进行中"
DEMO_NOTICE_EN = "PUBLIC DATA - entries labeled Simulated are simulated baselines; entries labeled Server-Verified are real probe records. Golden baselines are being calibrated."
DEMO_BANNER = (
    '<div style="position:sticky;top:0;z-index:9999;background:linear-gradient(90deg,#FFFBEB,#FEF3C7);color:#92400E;'
    'font:600 13px/1.5 system-ui,sans-serif;text-align:center;padding:8px 12px;'
    'border-bottom:1px solid #F59E0B">'
    "🌐 CSL-Meter 公开观测台 PUBLIC — " + DEMO_NOTICE_ZH + " · " + DEMO_NOTICE_EN + " (konspace.cc)</div>"
)

# ---------------------------------------------------------------------------
# GEO kit (v1.5.0): /llms.txt + /robots.txt + /sitemap.xml, all public.
# Content mirrors README.md / docs/methodology.md wording; no internal
# information. The two site-verification meta values are baked into the
# home page <head> (GOOGLE_SITE_VERIFICATION / BING_SITE_VERIFICATION).
# ---------------------------------------------------------------------------
GOOGLE_SITE_VERIFICATION = "1tBQmidYVGrz9zHr_PUhtJprdHrf-psjdJxIqIS2BD0"
BING_SITE_VERIFICATION = "D296B471A77449FE422315A5CBFDF675"
GITHUB_REPO_URL = "https://github.com/konspace-cc/csl-meter"

LLMS_TXT = """# CSL-Meter

> CSL-Meter is a public observatory that measures whether personal AI
> subscription plans and pay-as-you-go API plans actually serve the model
> they claim. It probes plans with real upstream API calls and publishes
> a CSL index per plan, with every reading labeled by origin.

## What CSL means

CSL = Consistency, Substitution & Latency. For each plan CSL-Meter runs
a fixed probe battery (real outbound API requests), extracts a numeric
distribution fingerprint from the responses, and compares it against a
golden baseline for the claimed model. The published CSL index combines
identification consistency across harnesses, substitution risk (the
fingerprint drifting towards a different model's profile) and latency.

## Data labeling rules (read this before citing any number)

- Simulated: simulated baseline data, seeded for display. It is NEVER
  mixed into verified aggregates.
- Server-Verified: produced by a real probe battery executed and stored
  by the server against the provider's official endpoint.
- A plan only counts as verified once it carries at least one
  Server-Verified sample; the site-wide status turns verified-live only
  once EVERY listed plan has one.
- If a number has no label, it is not a measurement.

## Key links

- Live site: https://konspace.cc/
- Plans API (JSON): https://konspace.cc/api/v1/plans
- Methodology: https://github.com/konspace-cc/csl-meter/blob/main/docs/methodology.md
- Source code (Apache-2.0): https://github.com/konspace-cc/csl-meter

## Calibration

The golden baselines are still being crowd-calibrated: if you hold a
first-party API key for a baseline model, you can contribute a
calibration capture — see CONTRIBUTING.md in the GitHub repository.
"""

ROBOTS_TXT = """# CSL-Meter (konspace.cc) - all crawlers welcome, including AI search.
User-agent: *
Allow: /

User-agent: GPTBot
Allow: /

User-agent: ChatGPT-User
Allow: /

User-agent: OAI-SearchBot
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Perplexity-User
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: anthropic-ai
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: CCBot
Allow: /

User-agent: Bingbot
Allow: /

Sitemap: https://konspace.cc/sitemap.xml
"""


def _sitemap_xml() -> str:
    # Only URLs that really exist as public routes: home and /llms.txt.
    # There is no standalone methodology page route (the methodology
    # lives in the GitHub repo), so it is not listed here.
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        "  <url><loc>https://konspace.cc/</loc></url>\n"
        "  <url><loc>https://konspace.cc/llms.txt</loc></url>\n"
        "</urlset>\n"
    )

db = CSLDatabase(DB_PATH)


class SlidingRateLimiter:
    """Dual-layer (per-IP and global) sliding window rate limiter."""

    def __init__(self):
        self._lock = threading.Lock()
        self._ip_hits = {}
        self._global_hits = []

    def allow(self, ip: str, is_write: bool = False) -> bool:
        now = time.time()
        window = 60.0
        ip_limit = 30 if is_write else 240
        global_limit = 150 if is_write else 1200
        with self._lock:
            self._global_hits = [t for t in self._global_hits if now - t < window]
            if len(self._global_hits) >= global_limit:
                return False
            hits = [t for t in self._ip_hits.get(ip, []) if now - t < window]
            if len(hits) >= ip_limit:
                self._ip_hits[ip] = hits
                return False
            hits.append(now)
            self._ip_hits[ip] = hits
            self._global_hits.append(now)
            return True


rate_limiter = SlidingRateLimiter()


def verify_turnstile_token(token: str, remote_ip: str) -> tuple:
    """
    Verify Cloudflare Turnstile token via official siteverify endpoint when TURNSTILE_SECRET_KEY is configured.
    """
    secret_key = os.environ.get("TURNSTILE_SECRET_KEY", "").strip()
    if not secret_key:
        # Fail closed: an earlier design passed the submission through when
        # no secret was configured (fail-open), so a lost env var silently
        # disabled the check. Without a secret the verification cannot run,
        # so the submission is rejected outright.
        return False, "TURNSTILE_SECRET_NOT_CONFIGURED: 服务器未配置 Turnstile 校验密钥，提交被拒绝。"

    if not token or not str(token).strip():
        return False, "TURNSTILE_TOKEN_MISSING: 请先完成页面上的 Cloudflare Turnstile 人机验证控件。"

    verify_url = _TEST_TURNSTILE_VERIFY_URL or "https://challenges.cloudflare.com/turnstile/v0/siteverify"
    form_data = urllib.parse.urlencode(
        {
            "secret": secret_key,
            "response": str(token).strip(),
            "remoteip": remote_ip or "",
        }
    ).encode("utf-8")

    req = urllib.request.Request(
        verify_url,
        data=form_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    ctx = ssl.create_default_context() if verify_url.startswith("https://") else None
    try:
        with urllib.request.urlopen(req, timeout=8.0, context=ctx) as resp:
            result = json.loads(resp.read().decode("utf-8", errors="replace"))
        if result.get("success") is True:
            return True, "ok"
        err_codes = ",".join(result.get("error-codes") or ["invalid-input-response"])
        return False, f"TURNSTILE_VERIFY_FAILED: 人机验证未通过 ({err_codes})。"
    except Exception as exc:
        return False, f"TURNSTILE_VERIFY_ERROR: 校验服务通信异常 ({type(exc).__name__})。"


def make_attribution(canonical_path: str, badge_path: str = None) -> dict:
    return {
        "source": BRAND_FULL,
        "site_url": SITE_DOMAIN,
        "api_url": API_DOMAIN,
        "canonical_url": f"{SITE_DOMAIN}{canonical_path}",
        "badge_svg": f"{SITE_DOMAIN}{badge_path}" if badge_path else f"{SITE_DOMAIN}/badge/plan/volcengine/coding-plan-lite.svg",
        "license": "CC-BY-4.0 (Must retain CSL-Meter attribution and link to konspace.cc)",
    }


def make_data_status_meta(has_verified: bool) -> dict:
    if has_verified:
        return {
            "data_status": "verified-live",
            "data_notice": "包含经真实上游 API 探测生成的 Server-Verified 样本数据。",
        }
    return {
        "data_status": "demo-simulated",
        "data_notice": "当前展示为初始演示基线（Simulated · 模拟生成）；提交真实 API Key 完成上游调用后将生成 Server-Verified 实测记录。",
    }


def _global_data_status_meta() -> dict:
    """Site-wide data_status, strict rule.

    A permissive rule would flip the global status to verified-live as soon
    as ANY plan had a verified sample. That is too coarse: the global status
    flips only once EVERY plan carries at least one Server-Verified sample
    (a plan's aggregate row switches data_origin on its first real sample).
    While any plan is still on the simulated baseline, the site as a whole
    stays demo-simulated. Per-plan / per-report meta are unaffected.
    """
    total = db.count_plans()
    verified = db.count_verified_plans()
    return make_data_status_meta(total > 0 and verified >= total)


SHARED_CSS = """
:root {
  --bg-canvas: #F5F8FD;
  --bg-surface: #FFFFFF;
  --bg-elevated: #EDF2FA;
  --border-subtle: #E2E8F2;
  --border-focus: #6D5DF6;
  --text-primary: #0C1222;
  --text-body: #1E293B;
  --text-muted: #64748B;
  --accent-blue: #2E6BFF;
  --accent-bright: #7C3AED;
  --accent-dim: rgba(46, 107, 255, 0.08);
  --accent-start: #2E6BFF;
  --accent-end: #7C3AED;
  --accent-gradient: linear-gradient(135deg, #2E6BFF 0%, #6D5DF6 55%, #7C3AED 100%);
  --shadow-sm: 0 1px 2px rgba(16, 24, 40, 0.05);
  --shadow-md: 0 4px 16px rgba(16, 24, 40, 0.07), 0 1px 3px rgba(16, 24, 40, 0.05);
  --shadow-lg: 0 12px 32px rgba(16, 24, 40, 0.10), 0 2px 6px rgba(16, 24, 40, 0.06);
  --radius-card: 16px;
  --radius-pill: 999px;
  --font-sans: 'Google Sans', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Noto Sans CJK SC', 'PingFang SC', 'Microsoft YaHei', sans-serif;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, 'JetBrains Mono', 'DejaVu Sans Mono', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  background-color: var(--bg-canvas);
  background-image: radial-gradient(1200px 420px at 50% -120px, rgba(46, 107, 255, 0.14), rgba(124, 58, 237, 0.08) 45%, transparent 70%);
  background-repeat: no-repeat;
  color: var(--text-body);
  font-family: var(--font-sans);
  font-size: 15px;
  line-height: 1.55;
  -webkit-font-smoothing: antialiased;
}
a { color: var(--accent-blue); text-decoration: none; }
a:hover { text-decoration: underline; }
.mono, .num {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-feature-settings: "tnum" 1, "zero" 1;
}
.demo-banner {
  background: linear-gradient(90deg, #FFFBEB, #FEF3C7);
  border-bottom: 1px solid #F59E0B;
  color: #92400E;
  font-size: 13px;
  padding: 9px 20px;
  text-align: center;
}
.demo-banner strong { color: #78350F; }
.shell {
  max-width: 1380px;
  margin: 0 auto;
  padding: 0 20px 48px;
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 12px;
  padding: 18px 0;
  border-bottom: 1px solid var(--border-subtle);
  margin-bottom: 22px;
}
.brand-wrap {
  display: flex;
  align-items: center;
  gap: 12px;
  flex-wrap: wrap;
}
.brand-badge {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--accent-gradient);
  border: 0;
  color: #FFFFFF;
  font-family: var(--font-sans);
  font-weight: 700;
  font-size: 14px;
  padding: 6px 14px;
  border-radius: var(--radius-pill);
  box-shadow: var(--shadow-sm);
}
.brand-title {
  color: var(--text-primary);
  font-weight: 700;
  font-size: 15px;
}
.brand-sub {
  color: var(--text-muted);
  font-size: 13px;
}
.nav-links {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.nav-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 7px 14px;
  border-radius: var(--radius-pill);
  font-size: 13px;
  font-weight: 600;
  color: var(--text-body);
  background: rgba(255, 255, 255, 0.85);
  border: 1px solid var(--border-subtle);
  cursor: pointer;
  transition: background 0.15s ease, color 0.15s ease, border-color 0.15s ease;
}
.nav-btn:hover {
  border-color: var(--accent-blue);
  color: var(--accent-blue);
  text-decoration: none;
}
.nav-btn.active {
  border-color: transparent;
  color: #FFFFFF;
  background: var(--accent-gradient);
  text-decoration: none;
}
.kpi-strip {
  display: grid;
  grid-template-columns: repeat(4, 1fr);
  gap: 16px;
  margin-bottom: 20px;
}
.kpi-card {
  background: rgba(255, 255, 255, 0.82);
  backdrop-filter: blur(12px);
  -webkit-backdrop-filter: blur(12px);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-card);
  padding: 18px 20px;
  box-shadow: var(--shadow-sm);
  transition: transform 0.15s ease, box-shadow 0.15s ease;
}
.kpi-card:hover {
  transform: translateY(-2px);
  box-shadow: var(--shadow-md);
}
.kpi-label {
  color: var(--text-muted);
  font-size: 12px;
  text-transform: uppercase;
  letter-spacing: 0.04em;
  margin-bottom: 6px;
}
.kpi-val {
  color: var(--accent-blue);
  font-size: 30px;
  font-weight: 800;
  font-family: var(--font-sans);
  font-variant-numeric: tabular-nums;
  white-space: nowrap;
  line-height: 1.2;
}
@supports ((background-clip: text) or (-webkit-background-clip: text)) {
  .kpi-val {
    background: var(--accent-gradient);
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
    color: transparent;
  }
}
.kpi-foot {
  color: var(--text-muted);
  font-size: 12px;
  margin-top: 4px;
}
.panel {
  background: rgba(255, 255, 255, 0.85);
  backdrop-filter: blur(8px);
  -webkit-backdrop-filter: blur(8px);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-card);
  margin-bottom: 20px;
  overflow: hidden;
  box-shadow: var(--shadow-sm);
}
.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 14px 18px;
  background: #F8FAFE;
  border-bottom: 1px solid var(--border-subtle);
  flex-wrap: wrap;
  gap: 10px;
}
.panel-title {
  color: var(--text-primary);
  font-weight: 700;
  font-size: 16px;
  display: flex;
  align-items: center;
  gap: 8px;
}
.filter-bar {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}
.tab-pill {
  padding: 6px 14px;
  border-radius: var(--radius-pill);
  font-size: 13px;
  font-weight: 600;
  color: var(--text-muted);
  background: #FFFFFF;
  border: 1px solid var(--border-subtle);
  transition: background 0.15s ease, color 0.15s ease;
}
.tab-pill.active, .tab-pill:hover {
  color: #FFFFFF;
  border-color: transparent;
  background: var(--accent-gradient);
  text-decoration: none;
}
.data-table-wrap {
  width: 100%;
  overflow-x: auto;
}
table.data-table {
  width: 100%;
  border-collapse: collapse;
  text-align: left;
}
table.data-table th {
  background: #F8FAFE;
  color: var(--text-muted);
  font-weight: 600;
  font-size: 12px;
  padding: 10px 8px;
  border-bottom: 1px solid var(--border-subtle);
  white-space: nowrap;
}
table.data-table th a {
  color: var(--text-muted);
  display: inline-flex;
  align-items: center;
  gap: 4px;
}
table.data-table th a.sorted, table.data-table th a:hover {
  color: var(--accent-blue);
  text-decoration: none;
}
table.data-table td {
  padding: 10px 8px;
  border-bottom: 1px solid var(--border-subtle);
  color: var(--text-body);
  font-size: 13px;
  white-space: nowrap;
}
table.data-table tr:hover td {
  background: #F1F5FE;
}
table.data-table td.num, table.data-table th.num {
  text-align: right;
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
}
.csl-bar-wrap {
  display: inline-flex;
  align-items: center;
  gap: 8px;
  justify-content: flex-end;
}
.csl-bar-bg {
  width: 48px;
  height: 8px;
  background: var(--bg-elevated);
  border: 1px solid var(--border-subtle);
  border-radius: var(--radius-pill);
  overflow: hidden;
}
.csl-bar-fill {
  height: 100%;
  background: var(--accent-gradient);
}
/* Provider / plan cell: full name wraps to two lines, no ellipsis (all screens). */
table.data-table td.provider-cell { white-space: normal; max-width: 190px; }
table.data-table td.provider-cell .plan-name {
  white-space: normal; word-break: break-word; line-height: 1.35;
}
@media (min-width: 721px) {
  /* Desktop table density (v1.5.6): fit both home tables in the 1380px shell
     without horizontal scroll; mobile (<=720px) untouched. */
  table.data-table th { padding: 8px 5px; font-size: 11px; }
  table.data-table td { padding: 8px 5px; font-size: 12px; }
  table.data-table td.tput-cell { line-height: 1.35; }
  table.data-table td.tput-cell .tput-sub {
    font-size: 11px; color: var(--text-muted);
  }
  .csl-bar-bg { width: 40px; }
  .csl-bar-wrap { gap: 6px; }
}
.tag-chip {
  display: inline-block;
  padding: 3px 10px;
  border-radius: var(--radius-pill);
  font-family: var(--font-mono);
  font-size: 11px;
  font-weight: 600;
  color: var(--accent-blue);
  background: var(--accent-dim);
  border: 1px solid rgba(46, 107, 255, 0.30);
  white-space: nowrap;
}
.tag-simulated {
  color: #92400E;
  background: #FEF3C7;
  border: 1px solid rgba(245, 158, 11, 0.45);
}
.tag-verified {
  color: #166534;
  background: #DCFCE7;
  border: 1px solid rgba(34, 197, 94, 0.45);
}
.probe-grid {
  display: grid;
  grid-template-columns: repeat(6, 1fr);
  gap: 12px;
  padding: 18px;
  align-items: end;
}
.field-group {
  display: flex;
  flex-direction: column;
  gap: 5px;
}
.field-label {
  font-size: 12px;
  color: var(--text-muted);
  font-weight: 600;
}
.field-input, .field-select {
  background: #FFFFFF;
  border: 1px solid #CBD5E1;
  color: var(--text-primary);
  padding: 9px 12px;
  border-radius: 10px;
  font-size: 13px;
  font-family: var(--font-mono);
}
.field-input:focus, .field-select:focus {
  outline: none;
  border-color: var(--accent-blue);
  box-shadow: 0 0 0 3px rgba(46, 107, 255, 0.15);
}
.btn-submit {
  background: var(--accent-gradient);
  color: #FFFFFF;
  border: 0;
  padding: 10px 18px;
  border-radius: var(--radius-pill);
  font-weight: 700;
  font-size: 13px;
  cursor: pointer;
  font-family: var(--font-sans);
  transition: opacity 0.15s ease, transform 0.15s ease;
}
.btn-submit:hover {
  opacity: 0.92;
}
.notice-bar {
  padding: 10px 18px;
  background: #F8FAFE;
  border-top: 1px solid var(--border-subtle);
  color: var(--text-muted);
  font-size: 12px;
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: 8px;
}
.grid-2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: 16px;
}
.code-box {
  background: #F1F5F9;
  border: 1px solid var(--border-subtle);
  border-radius: 10px;
  padding: 10px 12px;
  font-family: var(--font-mono);
  font-size: 12px;
  color: var(--text-body);
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.5;
}
.dist-row {
  display: grid;
  grid-template-columns: 48px 1fr 110px;
  align-items: center;
  gap: 10px;
  padding: 6px 0;
  border-bottom: 1px solid rgba(226, 232, 242, 0.7);
}
.dual-bar-track {
  display: flex;
  flex-direction: column;
  gap: 3px;
}
.bar-obs {
  height: 7px;
  background: var(--accent-gradient);
  border-radius: 2px;
}
.bar-ref {
  height: 7px;
  background: #CBD5E1;
  border-radius: 2px;
}
.footer {
  margin-top: 28px;
  padding-top: 16px;
  border-top: 1px solid var(--border-subtle);
  display: flex;
  justify-content: space-between;
  color: var(--text-muted);
  font-size: 12px;
  flex-wrap: wrap;
  gap: 10px;
}
@media (max-width: 720px) {
  .shell { padding: 0 12px 32px; }
  .topbar { flex-wrap: wrap; padding: 14px 0; margin-bottom: 16px; }
  .brand-wrap { flex-wrap: wrap; }
  .nav-links { flex-wrap: wrap; }
  .kpi-strip { grid-template-columns: repeat(2, 1fr); gap: 12px; }
  .kpi-val { font-size: 24px; }
  .probe-grid { grid-template-columns: repeat(2, 1fr); padding: 14px; }
  .grid-2 { grid-template-columns: minmax(0, 1fr); }
  .panel-head { padding: 12px 14px; }
}
@media (max-width: 480px) {
  .kpi-strip { grid-template-columns: minmax(0, 1fr); }
  .probe-grid { grid-template-columns: minmax(0, 1fr); }
  .nav-btn { padding: 6px 10px; font-size: 12px; }
}
"""


def render_header(active_nav: str = "table") -> str:
    return f"""
    <header class="topbar">
      <div class="brand-wrap">
        <a href="/" class="brand-badge" style="text-decoration:none;">⚡ CSL-Meter</a>
        <div>
          <div class="brand-title">个人大模型套餐与按量接口 CSL 指数公共观测台</div>
          <div class="brand-sub">Consistency, Substitution &amp; Latency Meter · 零凭证落盘 · 众包峰谷时序基准 (<span class="mono">konspace.cc</span>)</div>
        </div>
      </div>
      <nav class="nav-links">
        <a href="/" class="nav-btn {'active' if active_nav == 'table' else ''}">套餐与 Provider 总表</a>
        <a href="/timeline" class="nav-btn {'active' if active_nav == 'timeline' else ''}">24h 峰谷与 30d 趋势</a>
        <a href="/r/a49d2e" class="nav-btn {'active' if active_nav == 'report' else ''}">实测快照样例 (#a49d2e)</a>
        <a href="/api/v1/plans" class="nav-btn mono">JSON API</a>
      </nav>
    </header>
    """


def render_home_page(query_params: dict) -> str:
    cat = query_params.get("category", ["all"])[0]
    sort_by = query_params.get("sort", ["sample_count_7d"])[0]
    order = query_params.get("order", ["desc"])[0]
    origin_filter = query_params.get("origin", ["all"])[0]
    only_verified = origin_filter == "verified"

    plans = db.list_plans(category=cat, sort_by=sort_by, order=order, only_verified=only_verified)
    recent_reports = db.list_recent_reports(limit=6, only_verified=only_verified)
    verified_total = db.count_verified_reports()
    site_key = os.environ.get("TURNSTILE_SITE_KEY", "").strip()

    def sort_link(col_key: str, label: str, is_num: bool = True, title: str = "") -> str:
        next_ord = "asc" if (sort_by == col_key and order == "desc") else "desc"
        arrow = ""
        cls = ""
        if sort_by == col_key:
            arrow = " ↓" if order == "desc" else " ↑"
            cls = "sorted"
        th_cls = 'class="num"' if is_num else ""
        title_attr = f' title="{html.escape(title)}"' if title else ""
        return f'<th {th_cls}><a class="{cls}"{title_attr} href="/?category={html.escape(cat)}&amp;origin={html.escape(origin_filter)}&amp;sort={col_key}&amp;order={next_ord}">{label}{arrow}</a></th>'

    rows_html = []
    if not plans:
        rows_html.append(
            '<tr><td colspan="12" style="text-align:center;padding:24px;color:var(--text-muted);">当前筛选条件下暂无真实已验真（Server-Verified）记录。请在上方探测台输入真实 API Key 发起首次实测，或切换至「含演示基线」视图。</td></tr>'
        )
    for p in plans:
        p_slug = html.escape(p["provider_slug"])
        pl_slug = html.escape(p["plan_slug"])
        csl = p["csl_index_7d"]
        bar_w = min(100, max(6, int(csl * 1.8)))
        is_sim = p.get("data_origin") != "Server-Verified"
        origin_tag = "Simulated" if is_sim else f"Verified({p.get('verified_sample_count', 1)})"
        origin_chip_cls = "tag-chip tag-simulated" if is_sim else "tag-chip tag-verified"

        rows_html.append(
            f"""
            <tr>
              <td class="provider-cell" title="{html.escape(p['provider_name'])} — {html.escape(p['plan_name'])}">
                <div style="font-weight:600;color:var(--text-primary);white-space:nowrap;">{html.escape(p['provider_name'])}</div>
                <div class="plan-name" style="color:var(--text-muted);font-size:11px;">{html.escape(p['plan_name'])}</div>
              </td>
              <td><span class="{origin_chip_cls}">{origin_tag}</span></td>
              <td class="mono">{html.escape(p['claimed_model'])} <span style="color:var(--text-muted);">[{html.escape(p['harness_type'])}]</span></td>
              <td class="num">{p['sample_count_7d']}</td>
              <td class="num">
                <div class="csl-bar-wrap">
                  <div class="csl-bar-bg"><div class="csl-bar-fill" style="width:{bar_w}%;"></div></div>
                  <span style="color:var(--text-primary);font-weight:700;">{csl:.1f}</span>
                  <span style="color:var(--text-muted);font-size:11px;">±{p['csl_iqr']:.1f}</span>
                </div>
              </td>
              <td class="num" title="±{p['jsd_std']:.3f}">{p['net_jsd']:.3f}</td>
              <td class="num">{p['split_jsd']:.3f} <span style="color:var(--text-muted);">({p['tail_ratio']:.0f}%)</span></td>
              <td class="mono">{html.escape(p['nearest_profile'])}</td>
              <td class="num">+{p['peak_delta_csl']:.1f}</td>
              <td class="num">{p['token_ratio']:.2f}x <span style="color:var(--text-muted);">({p['cache_hit_pct']:.0f}%)</span></td>
              <td class="num tput-cell"><div>{p['median_tps']:.0f}T</div><div class="tput-sub">{p['ttft_ms']}ms · {p['rate_429_pct']:.1f}%</div></td>
              <td class="num">
                <a href="/timeline?p1={p_slug}/{pl_slug}" class="mono" style="font-size:11px;">峰谷</a> ·
                <a href="/badge/plan/{p_slug}/{pl_slug}.svg" class="mono" style="font-size:11px;" target="_blank">徽章</a>
              </td>
            </tr>
            """
        )

    plan_options_html = []
    for p in db.list_plans():
        val = f"{p['provider_slug']}|{p['plan_slug']}|{p['claimed_model']}|{p['harness_type']}"
        label = f"{p['provider_name']} — {p['plan_name']} [{p['claimed_model']}]"
        plan_options_html.append(f'<option value="{html.escape(val)}">{html.escape(label)}</option>')

    recent_rows_html = []
    for r in recent_reports:
        rid = html.escape(r["uuid"])
        vmode = "Server-Verified" if r.get("data_origin") == "Server-Verified" else "Simulated · 模拟生成"
        recent_rows_html.append(
            f"""
            <tr>
              <td class="mono"><a href="/r/{rid}">#{rid}</a></td>
              <td class="mono" style="color:var(--text-muted);">{html.escape(r['created_at'])}</td>
              <td class="provider-cell" title="{html.escape(r['provider_name'])} · {html.escape(r['plan_name'])}">{html.escape(r['provider_name'])} · {html.escape(r['plan_name'])}</td>
              <td class="mono">{html.escape(r['claimed_model'])}</td>
              <td class="mono" style="color:var(--text-muted);">{html.escape(vmode)}</td>
              <td class="num" style="color:var(--text-primary);font-weight:700;">{r['csl_index']:.1f}</td>
              <td class="num">{r['net_jsd']:.3f}</td>
              <td class="num">{r['split_jsd']:.3f}</td>
              <td class="mono">{html.escape(r['nearest_profile'])}</td>
              <td class="num">{r['tps']:.1f} TPS</td>
              <td class="num"><a href="/r/{rid}" class="mono">查看快照 →</a></td>
            </tr>
            """
        )

    turnstile_head_script = (
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        if site_key
        else ""
    )
    turnstile_widget_html = (
        f'<div class="cf-turnstile" data-sitekey="{html.escape(site_key)}" data-theme="light"></div>'
        if site_key
        else '<div class="mono" style="font-size:11px;color:var(--text-muted);padding:6px 8px;border:1px solid var(--border-subtle);border-radius:4px;background:var(--bg-canvas);">Turnstile 控件就绪 (待注入 TURNSTILE_SITE_KEY)</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CSL-Meter｜个人大模型套餐与按量接口 CSL 指数公共观测台 (konspace.cc)</title>
  <meta name="description" content="CSL-Meter probes AI subscription &amp; API plans for model consistency, substitution risk and latency — measured, not claimed."/>
  <link rel="canonical" href="https://konspace.cc/"/>
  <meta property="og:title" content="CSL-Meter — AI plan consistency, substitution &amp; latency, measured"/>
  <meta property="og:description" content="CSL-Meter probes AI subscription &amp; API plans for model consistency, substitution risk and latency — measured, not claimed."/>
  <meta property="og:url" content="https://konspace.cc/"/>
  <meta property="og:type" content="website"/>
  <meta name="google-site-verification" content="{GOOGLE_SITE_VERIFICATION}"/>
  <meta name="msvalidate.01" content="{BING_SITE_VERIFICATION}"/>
  <script type="application/ld+json">{{"@context": "https://schema.org", "@type": "Organization", "name": "CSL-Meter", "url": "https://konspace.cc/", "sameAs": ["{GITHUB_REPO_URL}"]}}</script>
  <script type="application/ld+json">{{"@context": "https://schema.org", "@type": "WebSite", "name": "CSL-Meter", "url": "https://konspace.cc/"}}</script>
  <style>{SHARED_CSS}</style>
  {turnstile_head_script}
</head>
<body>
  <div class="shell">
    {render_header("table")}

    <section class="kpi-strip">
      <div class="kpi-card">
        <div class="kpi-label">已收录个人套餐与按量靶标</div>
        <div class="kpi-val">{len(INITIAL_PLANS)} 个靶标</div>
        <div class="kpi-foot">仅限个人 Coding Plan / Token Plan / Pay-as-you-go（排除企业版）</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">真实上游 API 验真样本数</div>
        <div class="kpi-val">{verified_total} 条</div>
        <div class="kpi-foot">真实出站调用 · 假 Key 或断网直接拒绝入库 (绝不合成伪造报告)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">单次真探针并发与预算</div>
        <div class="kpi-val">≤4 路 / 硬顶 30K T</div>
        <div class="kpi-foot">14 次分布采样（256 T/发，推理感知提取）+ 2 次分词/缓存对账（单轮硬顶 30,000 Tokens）</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">凭证落盘残留检出数</div>
        <div class="kpi-val">0 条</div>
        <div class="kpi-foot">官方 API 域名严格白名单防 SSRF · 内存用完即焚</div>
      </div>
    </section>

    <section class="panel" id="probe-panel">
      <div class="panel-head">
        <div class="panel-title">
          <span>⚡ 发起真实上游 API 探测（真实出站请求 · 零凭证留存 · 拒绝假 Key 合成）</span>
        </div>
        <div class="mono" style="font-size:11px;color:var(--text-muted);">
          温和并发 4 路 · 16 次真实请求 (~1,100 Tokens) · Cloudflare Turnstile 服务端校验
        </div>
      </div>
      <form id="probe-form" onsubmit="return submitProbe(event);">
        <div class="probe-grid">
          <div class="field-group" style="grid-column: span 2;">
            <label class="field-label">1. 选择白名单个人套餐 / 官方按量基线（禁止自定义 URL 防 SSRF）</label>
            <select id="plan-selector" class="field-select" required>
              {''.join(plan_options_html)}
            </select>
          </div>
          <div class="field-group">
            <label class="field-label">2. 当前 5h 额度窗口水位标签</label>
            <select id="quota-stage" class="field-select">
              <option value="window_early (&lt;30%)">窗口初期 (&lt;30% 用量)</option>
              <option value="window_late (&gt;70%)">窗口中后期 (&gt;70% 用量)</option>
              <option value="fallback_triggered">触发降速 / 额度回退后</option>
            </select>
          </div>
          <div class="field-group">
            <label class="field-label">3. 临时测试凭证 (真实调用官方端点)</label>
            <input id="api-key-input" type="password" class="field-input" placeholder="sk-... (内存即焚)" required minlength="6" autocomplete="off"/>
          </div>
          <div class="field-group">
            <label class="field-label">4. 人机验证 (Cloudflare Turnstile)</label>
            {turnstile_widget_html}
          </div>
          <div class="field-group">
            <button type="submit" id="submit-btn" class="btn-submit">发起真实探测 →</button>
          </div>
        </div>
      </form>
      <div class="notice-bar">
        <span>验真边界：服务端使用该凭证向对应官方白名单 API 发起 16 次真实请求（耗时约 4–10 秒）；若 Key 无效或上游返回 401/403，直接报错且不生成任何报告。</span>
        <span id="probe-status" class="mono" style="color:var(--accent-bright);">等待提交真实测试凭证...</span>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div class="panel-title">
          <span>全局个人套餐与 Provider 客观统计总表（平铺直叙 · 按数据说话）</span>
        </div>
        <div class="filter-bar">
          <a href="/?category={html.escape(cat)}&amp;origin=all&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if not only_verified else ''}">含演示基线</a>
          <a href="/?category={html.escape(cat)}&amp;origin=verified&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if only_verified else ''}">仅看真实探测 ({verified_total})</a>
          <span style="color:var(--border-subtle);">|</span>
          <a href="/?category=all&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'all' else ''}">全部</a>
          <a href="/?category=cn_plan&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'cn_plan' else ''}">国内个人套餐</a>
          <a href="/?category=global_coding&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'global_coding' else ''}">海外 Coding 订阅</a>
          <a href="/?category=global_oa&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'global_oa' else ''}">海外 OA+Grok</a>
          <a href="/?category=payg&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'payg' else ''}">官方按量基线</a>
        </div>
      </div>
      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              {sort_link('provider_name', 'Provider / 个人套餐', False)}
              <th>数据状态</th>
              <th>宣称模型 [壳]</th>
              {sort_link('sample_count_7d', '样本 N')}
              {sort_link('csl_index_7d', 'CSL 指数')}
              {sort_link('net_jsd', 'Net-JSD')}
              {sort_link('split_jsd', 'Split-JSD')}
              <th>最接近基线 (Top-1)</th>
              {sort_link('peak_delta_csl', '峰谷 Δ')}
              {sort_link('token_ratio', '计费/缓存')}
              {sort_link('median_tps', '吞吐', title='吞吐 / TTFT / 429率')}
              <th class="num">引用</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows_html)}
          </tbody>
        </table>
      </div>
      <div class="notice-bar">
        <span>说明：标注 Simulated 的行为初始演示基线（不与真实探测混算）；一旦某套餐收到真实探测完成入库，该行自动切换为 Verified 并仅聚合真实测量值。</span>
        <span class="mono">实时 SVG 徽章示例：<img src="/badge/plan/volcengine/coding-plan-lite.svg" alt="CSL-Meter Badge" style="vertical-align:middle;height:20px;"/></span>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div class="panel-title"><span>入库快照流水（明确区分 Server-Verified 与 Simulated · 模拟生成）</span></div>
        <a href="/r/a49d2e" class="mono" style="font-size:11px;">查看快照样例 #a49d2e →</a>
      </div>
      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>快照 ID</th>
              <th>采样时间 (UTC)</th>
              <th>套餐名称</th>
              <th>宣称模型</th>
              <th>数据验真状态</th>
              <th class="num">CSL 指数</th>
              <th class="num">Net-JSD</th>
              <th class="num">Split-JSD</th>
              <th>最接近底座分布</th>
              <th class="num">实测吞吐</th>
              <th class="num">操作</th>
            </tr>
          </thead>
          <tbody>
            {''.join(recent_rows_html)}
          </tbody>
        </table>
      </div>
    </section>

    <footer class="footer">
      <div>⚡ <strong>CSL-Meter</strong> (Consistency, Substitution &amp; Latency Meter) · 生产主站 <a href="https://konspace.cc">https://konspace.cc</a> · API <a href="https://api.konspace.cc">https://api.konspace.cc</a></div>
      <div class="mono">CC-BY-4.0 · 引用数据请保留 CSL-Meter 徽章或回跳链接</div>
    </footer>
  </div>

  <script>
  async function submitProbe(e) {{
    e.preventDefault();
    const form = document.getElementById('probe-form');
    const sel = document.getElementById('plan-selector').value.split('|');
    const stage = document.getElementById('quota-stage').value;
    const keyInput = document.getElementById('api-key-input');
    const statusEl = document.getElementById('probe-status');
    const btn = document.getElementById('submit-btn');
    const tsInput = form.querySelector('[name="cf-turnstile-response"]');
    const tsToken = tsInput ? tsInput.value : '';

    const apiKeyVal = keyInput.value;
    keyInput.value = '';
    btn.disabled = true;
    statusEl.textContent = '正在向官方白名单端点发起 16 次真实 HTTP 探针请求，请稍候 (约 4–10 秒)...';

    try {{
      const resp = await fetch('/api/v1/probe', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{
          provider_slug: sel[0],
          plan_slug: sel[1],
          claimed_model: sel[2],
          harness_type: sel[3],
          quota_window_stage: stage,
          api_key: apiKeyVal,
          cf_turnstile_response: tsToken
        }})
      }});
      const data = await resp.json();
      if (!resp.ok) {{
        statusEl.textContent = '探测未通过: ' + (data.error || resp.statusText);
        btn.disabled = false;
        return false;
      }}
      statusEl.textContent = '真实探测完成！已生成快照 #' + data.report.uuid + '，正在跳转...';
      window.location.href = '/r/' + data.report.uuid;
    }} catch (err) {{
      statusEl.textContent = '请求异常: ' + err;
      btn.disabled = false;
    }}
    return false;
  }}
  </script>
</body>
</html>"""


def render_timeline_page(query_params: dict) -> str:
    p1_param = query_params.get("p1", ["volcengine/coding-plan-lite"])[0]
    p2_param = query_params.get("p2", ["openai/payg-official"])[0]
    mode = query_params.get("mode", ["hourly_24h"])[0]
    if mode not in ("hourly_24h", "daily_30d"):
        mode = "hourly_24h"

    def parse_pair(s: str, default_p: str, default_pl: str) -> tuple:
        if "/" in s:
            parts = s.split("/", 1)
            return parts[0], parts[1]
        return default_p, default_pl

    p1_prov, p1_plan = parse_pair(p1_param, "volcengine", "coding-plan-lite")
    p2_prov, p2_plan = parse_pair(p2_param, "openai", "payg-official")

    meta1 = db.get_plan(p1_prov, p1_plan) or db.get_plan("volcengine", "coding-plan-lite")
    meta2 = db.get_plan(p2_prov, p2_plan) or db.get_plan("openai", "payg-official")
    series1 = db.get_timeline(meta1["provider_slug"], meta1["plan_slug"], mode)
    series2 = db.get_timeline(meta2["provider_slug"], meta2["plan_slug"], mode)

    all_plans = db.list_plans()

    def build_options(selected_prov: str, selected_plan: str) -> str:
        opts = []
        for p in all_plans:
            val = f"{p['provider_slug']}/{p['plan_slug']}"
            sel = "selected" if (p["provider_slug"] == selected_prov and p["plan_slug"] == selected_plan) else ""
            opts.append(f'<option value="{html.escape(val)}" {sel}>{html.escape(p["provider_name"])} — {html.escape(p["plan_name"])}</option>')
        return "".join(opts)

    w, h = 920, 240
    pad_l, pad_r, pad_t, pad_b = 46, 24, 24, 34
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    n_pts = max(1, len(series1))

    def pt_coords(series: list) -> str:
        pts = []
        for idx, item in enumerate(series):
            x = pad_l + (idx / max(1, n_pts - 1)) * plot_w
            y = pad_t + plot_h - (min(40.0, max(0.0, item["csl_index"])) / 40.0) * plot_h
            pts.append(f"{x:.1f},{y:.1f}")
        return " ".join(pts)

    poly1 = pt_coords(series1)
    poly2 = pt_coords(series2)

    peak_rect = ""
    if mode == "hourly_24h" and n_pts >= 24:
        x1 = pad_l + (14 / 23.0) * plot_w
        x2 = pad_l + (18 / 23.0) * plot_w
        peak_rect = f'<rect x="{x1:.1f}" y="{pad_t}" width="{x2 - x1:.1f}" height="{plot_h}" fill="rgba(46, 107, 255, 0.10)" stroke="rgba(124, 58, 237, 0.35)" stroke-dasharray="3,3"/>'
        peak_rect += f'<text x="{(x1+x2)/2:.1f}" y="{pad_t + 14}" fill="#2E6BFF" font-size="10" font-family="monospace" text-anchor="middle">14:00-18:00 算力高峰带</text>'

    x_labels_svg = []
    step = 2 if mode == "hourly_24h" else 3
    for idx, item in enumerate(series1):
        if idx % step == 0 or idx == n_pts - 1:
            x = pad_l + (idx / max(1, n_pts - 1)) * plot_w
            x_labels_svg.append(
                f'<text x="{x:.1f}" y="{h - 10}" fill="#64748B" font-size="10" font-family="monospace" text-anchor="middle">{html.escape(item["bucket_label"])}</text>'
            )

    heat_cells = []
    for item in series1:
        csl_v = item["csl_index"]
        alpha = min(0.85, max(0.12, (csl_v - 6.0) / 24.0))
        heat_cells.append(
            f"""
            <div style="background:rgba(46, 107, 255, {alpha:.2f});border:1px solid var(--border-subtle);border-radius:4px;padding:6px 4px;text-align:center;">
              <div class="mono" style="font-size:10px;color:var(--text-muted);">{html.escape(item['bucket_label'])}</div>
              <div class="mono" style="font-size:12px;font-weight:700;color:var(--text-primary);margin-top:2px;">{csl_v:.1f}</div>
              <div class="mono" style="font-size:10px;color:var(--text-body);">{item['tps']:.0f}T</div>
            </div>
            """
        )

    table_rows = []
    for idx in range(min(len(series1), len(series2))):
        s1 = series1[idx]
        s2 = series2[idx]
        diff = s1["csl_index"] - s2["csl_index"]
        table_rows.append(
            f"""
            <tr>
              <td class="mono">{html.escape(s1['bucket_label'])}</td>
              <td class="num" style="color:var(--accent-bright);font-weight:600;">{s1['csl_index']:.1f}</td>
              <td class="num">{s1['net_jsd']:.3f}</td>
              <td class="num">{s1['tps']:.1f} TPS ({s1['rate_429_pct']:.1f}%)</td>
              <td class="num" style="color:var(--text-primary);font-weight:600;">{s2['csl_index']:.1f}</td>
              <td class="num">{s2['net_jsd']:.3f}</td>
              <td class="num">{s2['tps']:.1f} TPS ({s2['rate_429_pct']:.1f}%)</td>
              <td class="num">{diff:+.1f}</td>
            </tr>
            """
        )

    p1_full = f"{meta1['provider_slug']}/{meta1['plan_slug']}"
    p2_full = f"{meta2['provider_slug']}/{meta2['plan_slug']}"

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>24h 峰谷热力带与 30d 历史漂移曲线｜CSL-Meter (konspace.cc)</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  <div class="shell">
    {render_header("timeline")}

    <section class="panel">
      <div class="panel-head">
        <div class="panel-title">
          <span>跨时段 CSL 指数监控台（24 小时算力峰谷热力带 &amp; 30 日版本漂移折线）</span>
        </div>
        <div class="filter-bar">
          <a href="/timeline?p1={html.escape(p1_full)}&amp;p2={html.escape(p2_full)}&amp;mode=hourly_24h" class="tab-pill {'active' if mode == 'hourly_24h' else ''}">24 小时峰谷切片 (UTC+8)</a>
          <a href="/timeline?p1={html.escape(p1_full)}&amp;p2={html.escape(p2_full)}&amp;mode=daily_30d" class="tab-pill {'active' if mode == 'daily_30d' else ''}">30 日历史漂移曲线</a>
        </div>
      </div>

      <form method="GET" action="/timeline" style="padding:12px 14px;border-bottom:1px solid var(--border-subtle);display:flex;gap:12px;align-items:end;flex-wrap:wrap;">
        <input type="hidden" name="mode" value="{html.escape(mode)}"/>
        <div class="field-group" style="flex:1;min-width:240px;">
          <label class="field-label">主观测套餐 (电光蓝实线 + 热力格)</label>
          <select name="p1" class="field-select">{build_options(meta1['provider_slug'], meta1['plan_slug'])}</select>
        </div>
        <div class="field-group" style="flex:1;min-width:240px;">
          <label class="field-label">对照基线套餐 (浅灰蓝虚线)</label>
          <select name="p2" class="field-select">{build_options(meta2['provider_slug'], meta2['plan_slug'])}</select>
        </div>
        <button type="submit" class="btn-submit">切换对比曲线</button>
      </form>

      <div style="padding:16px 14px;">
        <div style="margin-bottom:8px;display:flex;justify-content:space-between;font-size:12px;">
          <div>
            <span style="color:var(--accent-bright);font-weight:700;">━ 主观测：{html.escape(meta1['provider_name'])} · {html.escape(meta1['plan_name'])}</span>
            <span style="margin-left:18px;color:var(--text-muted);">┅ 对照：{html.escape(meta2['provider_name'])} · {html.escape(meta2['plan_name'])}</span>
          </div>
          <div class="mono" style="color:var(--text-muted);">纵轴: CSL 指数 (0–40) · 数值越低越贴近官方满血直连分布</div>
        </div>

        <svg viewBox="0 0 {w} {h}" style="width:100%;height:auto;background:var(--bg-canvas);border:1px solid var(--border-subtle);border-radius:4px;">
          <line x1="{pad_l}" y1="{pad_t}" x2="{w - pad_r}" y2="{pad_t}" stroke="#E2E8F2" stroke-width="1"/>
          <line x1="{pad_l}" y1="{pad_t + plot_h*0.5:.1f}" x2="{w - pad_r}" y2="{pad_t + plot_h*0.5:.1f}" stroke="#E2E8F2" stroke-width="1" stroke-dasharray="2,2"/>
          <line x1="{pad_l}" y1="{pad_t + plot_h - (15.0/40.0)*plot_h:.1f}" x2="{w - pad_r}" y2="{pad_t + plot_h - (15.0/40.0)*plot_h:.1f}" stroke="#0369A1" stroke-width="1" stroke-dasharray="4,4"/>
          <text x="{pad_l - 6}" y="{pad_t + 4}" fill="#64748B" font-size="10" font-family="monospace" text-anchor="end">40.0</text>
          <text x="{pad_l - 6}" y="{pad_t + plot_h*0.5 + 4:.1f}" fill="#64748B" font-size="10" font-family="monospace" text-anchor="end">20.0</text>
          <text x="{pad_l - 6}" y="{pad_t + plot_h - (15.0/40.0)*plot_h + 3:.1f}" fill="#2E6BFF" font-size="10" font-family="monospace" text-anchor="end">15.0</text>
          <text x="{pad_l - 6}" y="{pad_t + plot_h + 4}" fill="#64748B" font-size="10" font-family="monospace" text-anchor="end">0.0</text>
          {peak_rect}
          <polyline fill="none" stroke="#7C3AED" stroke-width="2" stroke-dasharray="5,4" points="{poly2}"/>
          <polyline fill="none" stroke="#2E6BFF" stroke-width="2.5" points="{poly1}"/>
          {''.join(x_labels_svg)}
        </svg>

        <div style="margin-top:14px;">
          <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;">
            主观测套餐（{html.escape(meta1['plan_name'])}）切片热力矩阵（上行为时段/日期，中行为 CSL 指数，下行为实测 TPS）：
          </div>
          <div style="display:grid;grid-template-columns:repeat(auto-fill, minmax(68px, 1fr));gap:6px;">
            {''.join(heat_cells)}
          </div>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div class="panel-title"><span>双套餐分时对账明细表</span></div>
        <span class="mono" style="font-size:11px;color:var(--text-muted);">API 端点: {API_DOMAIN}/v1/timeline?provider={html.escape(meta1['provider_slug'])}&amp;plan={html.escape(meta1['plan_slug'])}</span>
      </div>
      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th>时间切片</th>
              <th class="num">{html.escape(meta1['plan_name'])} · CSL</th>
              <th class="num">主观测 Net-JSD</th>
              <th class="num">主观测 TPS (429率)</th>
              <th class="num">{html.escape(meta2['plan_name'])} · CSL</th>
              <th class="num">对照 Net-JSD</th>
              <th class="num">对照 TPS (429率)</th>
              <th class="num">CSL 差值 (Δ)</th>
            </tr>
          </thead>
          <tbody>
            {''.join(table_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <footer class="footer">
      <div>⚡ <strong>CSL-Meter</strong> · 生产主站 <a href="https://konspace.cc">https://konspace.cc</a> · API <a href="https://api.konspace.cc">https://api.konspace.cc</a></div>
      <div class="mono">CC-BY-4.0 · 数据每 5 秒同步更新至动态徽章</div>
    </footer>
  </div>
</body>
</html>"""


def render_report_page(report_uuid: str) -> str:
    rep = db.get_report(report_uuid)
    if not rep:
        return None

    uid = html.escape(rep["uuid"])
    p_slug = html.escape(rep["provider_slug"])
    pl_slug = html.escape(rep["plan_slug"])
    obs = rep["observed_dist"]
    base = rep["baseline_dist"]
    is_sim = rep.get("data_origin") != "Server-Verified"
    vmode_display = "Simulated · 模拟生成" if is_sim else "Server-Verified"

    dist_rows_html = []
    for k in PROBE_BUCKETS:
        o_pct = obs.get(k, 0.0) * 100.0
        b_pct = base.get(k, 0.0) * 100.0
        o_w = min(100.0, o_pct * 2.4)
        b_w = min(100.0, b_pct * 2.4)
        dist_rows_html.append(
            f"""
            <div class="dist-row">
              <div class="mono" style="font-weight:700;color:var(--text-primary);">#{html.escape(k)}</div>
              <div class="dual-bar-track">
                <div class="bar-obs" style="width:{o_w:.1f}%;" title="采样占比 {o_pct:.1f}%"></div>
                <div class="bar-ref" style="width:{b_w:.1f}%;" title="官方基线 {b_pct:.1f}%"></div>
              </div>
              <div class="num" style="font-size:11px;">
                <span style="color:var(--accent-bright);font-weight:600;">{o_pct:.1f}%</span>
                <span style="color:var(--text-muted);"> / {b_pct:.1f}%</span>
              </div>
            </div>
            """
        )

    ranking_rows = []
    for item in rep["nearest_ranking"]:
        sim = item["similarity"]
        ranking_rows.append(
            f"""
            <tr>
              <td class="mono" style="font-weight:600;color:var(--text-primary);">{html.escape(item['model'])}</td>
              <td><span class="tag-chip">{html.escape(item['family'])}</span></td>
              <td class="num">{item['jsd']:.4f}</td>
              <td class="num">
                <div class="csl-bar-wrap">
                  <div class="csl-bar-bg"><div class="csl-bar-fill" style="width:{min(100, int(sim))}%;"></div></div>
                  <span style="color:var(--accent-bright);font-weight:700;">{sim:.1f}%</span>
                </div>
              </td>
            </tr>
            """
        )

    ascii_block = (
        f"╭─ ⚡ CSL-Meter (konspace.cc) 数据快照 (#{rep['uuid']}) ────────────────╮\n"
        f"│ 套餐: {rep['provider_name']} · {rep['plan_name'][:22]} │\n"
        f"│ 宣称模型: {rep['claimed_model']:<18} | 窗口位置: {rep['quota_window_stage']:<16} │\n"
        f"│ CSL 指数: {rep['csl_index']:<6.1f}             | 净分布距离 Net-JSD: {rep['net_jsd']:<6.3f} │\n"
        f"│ 最接近底座: {rep['nearest_profile']:<16} | 自切分离散度: {rep['split_jsd']:<6.3f}       │\n"
        f"│ 吞吐: {rep['tps']:<5.1f} TPS ({rep['rate_429_pct']:.1f}% 429)   | 缓存命中: {rep['cache_hit_pct']:.1f}% | 计费比: {rep['token_ratio']:.2f}x │\n"
        f"│ 数据状态: {vmode_display:<18} | 原始分布: {SITE_DOMAIN}/r/{rep['uuid']} │\n"
        f"╰───────────────────────────────────────────────────────────────╯"
    )

    md_badge_code = f"[![CSL-Meter]({SITE_DOMAIN}/badge/r/{rep['uuid']}.svg)]({SITE_DOMAIN}/r/{rep['uuid']})"
    md_plan_badge = f"[![CSL-Meter]({SITE_DOMAIN}/badge/plan/{p_slug}/{pl_slug}.svg)]({SITE_DOMAIN}/timeline?p1={p_slug}/{pl_slug})"
    iframe_code = f'<iframe src="{SITE_DOMAIN}/embed/r/{rep["uuid"]}" width="100%" height="220" frameborder="0"></iframe>'

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>快照 #{uid} ({html.escape(rep['plan_name'])})｜CSL-Meter (konspace.cc)</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  <div class="shell">
    {render_header("report")}

    <section class="kpi-strip">
      <div class="kpi-card">
        <div class="kpi-label">快照编号 / 套餐归属</div>
        <div class="kpi-val">#{uid}</div>
        <div class="kpi-foot">{html.escape(rep['provider_name'])} · {html.escape(rep['plan_name'])}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">CSL 指数 (0–100)</div>
        <div class="kpi-val" style="color:var(--accent-bright);">{rep['csl_index']:.1f}</div>
        <div class="kpi-foot">去壳净距离 Net-JSD: <span class="mono">{rep['net_jsd']:.3f}</span> (原始 JSD: <span class="mono">{rep['raw_jsd']:.3f}</span>)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">最接近黄金基线底座</div>
        <div class="kpi-val" style="font-size:17px;">{html.escape(rep['nearest_profile'])}</div>
        <div class="kpi-foot">次接近: {html.escape(rep['second_profile'])} · 自切分 JSD: <span class="mono">{rep['split_jsd']:.3f}</span></div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">数据状态与工程遥测</div>
        <div class="kpi-val" style="font-size:16px;">{html.escape(vmode_display)}</div>
        <div class="kpi-foot">{rep['tps']:.1f} TPS · TTFT: {rep['ttft_ms']}ms · 计费比: {rep['token_ratio']:.2f}x</div>
      </div>
    </section>

    <div class="grid-2">
      <section class="panel">
        <div class="panel-head">
          <div class="panel-title"><span>去壳校准后采样分布 vs 官方黄金基线 ({html.escape(rep['claimed_model'])})</span></div>
          <a href="/api/v1/reports/{uid}/raw.json" class="nav-btn mono" download="csl-meter-{uid}.json">下载原始频数 JSON ↓</a>
        </div>
        <div style="padding:14px;">
          <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text-muted);margin-bottom:8px;">
            <span>探针特征桶 (Canonical Buckets)</span>
            <span><strong style="color:var(--accent-bright);">■ 采样分布</strong> vs <strong>■ 官方基线</strong></span>
          </div>
          {''.join(dist_rows_html)}
        </div>
      </section>

      <section class="panel">
        <div class="panel-head">
          <div class="panel-title"><span>黄金基线库最近邻匹配排行 (Harness De-biased Top 5)</span></div>
          <span class="mono" style="font-size:11px;color:var(--text-muted);">工具壳: {html.escape(rep['harness_type'])} · {html.escape(rep['quota_window_stage'])}</span>
        </div>
        <div class="data-table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th>候选基线模型</th>
                <th>模型家族</th>
                <th class="num">净距离 Net-JSD</th>
                <th class="num">分布吻合度</th>
              </tr>
            </thead>
            <tbody>
              {''.join(ranking_rows)}
            </tbody>
          </table>
        </div>
        <div class="notice-bar">
          <span>采样时间: <span class="mono">{html.escape(rep['created_at'])}</span></span>
          <span>数据性质: <span class="mono">{html.escape(vmode_display)}</span></span>
        </div>
      </section>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div class="panel-title"><span>外部数据引用与社区扩散组件（强制自带 CSL-Meter / konspace.cc 标记）</span></div>
        <img src="/badge/r/{uid}.svg" alt="Snapshot Badge" style="height:22px;"/>
      </div>
      <div style="padding:14px;display:grid;grid-template-columns:minmax(0, 1.08fr) minmax(0, 0.92fr);gap:14px;">
        <div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <span class="field-label">1. 社区晒单专用【ASCII / Markdown 签名块】</span>
            <button type="button" class="nav-btn" onclick="copyText('ascii-sig', this)">一键复制签名块</button>
          </div>
          <pre id="ascii-sig" class="code-box">{html.escape(ascii_block)}</pre>
        </div>
        <div style="display:flex;flex-direction:column;gap:10px;">
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
              <span class="field-label">2. GitHub / 论坛动态 SVG 徽章 (单次快照 &amp; 套餐实时聚合)</span>
              <button type="button" class="nav-btn" onclick="copyText('badge-md', this)">复制 Markdown</button>
            </div>
            <pre id="badge-md" class="code-box">{html.escape(md_badge_code)}
{html.escape(md_plan_badge)}</pre>
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px;">
              <span class="field-label">3. 锁定品牌底栏的 Iframe 嵌入卡片</span>
              <button type="button" class="nav-btn" onclick="copyText('iframe-snippet', this)">复制 Iframe</button>
            </div>
            <pre id="iframe-snippet" class="code-box">{html.escape(iframe_code)}</pre>
          </div>
        </div>
      </div>
    </section>

    <footer class="footer">
      <div>⚡ <strong>CSL-Meter</strong> · 生产主站 <a href="https://konspace.cc">https://konspace.cc</a> · API <a href="https://api.konspace.cc">https://api.konspace.cc</a></div>
      <div class="mono">CC-BY-4.0 · 原始 JSON 与徽章接口开放调用</div>
    </footer>
  </div>
  <script>
  function copyText(id, btn) {{
    const txt = document.getElementById(id).innerText;
    navigator.clipboard.writeText(txt).then(() => {{
      const old = btn.innerText;
      btn.innerText = '已复制 ✓';
      setTimeout(() => {{ btn.innerText = old; }}, 1500);
    }});
  }}
  </script>
</body>
</html>"""


def render_embed_card(title: str, subtitle: str, csl_val: float, jsd_val: float, nearest: str, tps_val: float, n_val: int, target_url: str, is_demo: bool = True) -> str:
    demo_tag = " · DEMO" if is_demo else ""
    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8"/>
  <title>CSL-Meter Embed Card</title>
  <style>
    {SHARED_CSS}
    body {{ background: transparent; padding: 0; margin: 0; overflow: hidden; }}
    .embed-shell {{
      background: var(--bg-surface);
      border: 1px solid var(--border-focus);
      border-radius: 6px;
      height: 210px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      overflow: hidden;
    }}
    .embed-body {{ padding: 14px 16px; }}
    .embed-locked-bar {{
      height: 32px;
      background: var(--bg-canvas);
      border-top: 1px solid var(--border-subtle);
      padding: 0 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--accent-bright);
      user-select: none;
    }}
  </style>
</head>
<body>
  <div class="embed-shell">
    <div class="embed-body">
      <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:12px;">
        <div>
          <div style="color:var(--text-primary);font-weight:700;font-size:14px;">{html.escape(title)}</div>
          <div class="mono" style="color:var(--text-muted);font-size:11px;">{html.escape(subtitle)}</div>
        </div>
        <div class="brand-badge">CSL {csl_val:.1f}{demo_tag}</div>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4, 1fr);gap:8px;background:var(--bg-canvas);padding:10px;border-radius:4px;border:1px solid var(--border-subtle);">
        <div>
          <div style="font-size:10px;color:var(--text-muted);">净距离 Net-JSD</div>
          <div class="mono" style="font-size:14px;font-weight:700;color:var(--text-primary);">{jsd_val:.3f}</div>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text-muted);">最接近底座</div>
          <div class="mono" style="font-size:12px;font-weight:600;color:var(--accent-bright);">{html.escape(nearest)}</div>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text-muted);">中位吞吐</div>
          <div class="mono" style="font-size:14px;font-weight:700;color:var(--text-primary);">{tps_val:.1f} TPS</div>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text-muted);">样本计数</div>
          <div class="mono" style="font-size:14px;font-weight:700;color:var(--text-primary);">N = {n_val}{demo_tag}</div>
        </div>
      </div>
    </div>
    <div class="embed-locked-bar">
      <span>⚡ Telemetry by <strong>CSL-Meter</strong> (konspace.cc){demo_tag}</span>
      <a href="{html.escape(target_url)}" target="_blank" rel="noopener">查看原始分布与复现脚本 ↗</a>
    </div>
  </div>
</body>
</html>"""


def render_login_page(error: str = "") -> str:
    err_html = ""
    if error:
        err_html = '<p style="color:#DC2626;font-size:13px;margin:0 0 12px">' + html.escape(error) + "</p>"
    page = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>登录 · CSL-Meter (konspace.cc)</title>
<style>
body { margin:0; background:#F5F8FD; background-image:radial-gradient(900px 320px at 50% -100px, rgba(46,107,255,0.14), rgba(124,58,237,0.08) 45%, transparent 70%); background-repeat:no-repeat; color:#1E293B; font-family:system-ui,-apple-system,sans-serif; display:flex; min-height:100vh; align-items:center; justify-content:center; }
.card { background:rgba(255,255,255,0.88); backdrop-filter:blur(12px); -webkit-backdrop-filter:blur(12px); border:1px solid #E2E8F2; border-radius:16px; padding:32px 28px; width:min(92vw,360px); box-shadow:0 12px 32px rgba(16,24,40,0.10), 0 2px 6px rgba(16,24,40,0.06); }
h1 { font-size:20px; margin:0 0 6px; background:linear-gradient(135deg,#2E6BFF 0%,#6D5DF6 55%,#7C3AED 100%); -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; color:#2E6BFF; }
.sub { color:#64748B; font-size:13px; margin:0 0 20px; }
label { display:block; font-size:12px; color:#64748B; margin:0 0 6px; }
input { width:100%; box-sizing:border-box; background:#FFFFFF; border:1px solid #CBD5E1; border-radius:10px; color:#0C1222; padding:10px 12px; margin:0 0 16px; font-size:14px; }
input:focus { outline:none; border-color:#2E6BFF; box-shadow:0 0 0 3px rgba(46,107,255,0.15); }
button { width:100%; background:linear-gradient(135deg,#2E6BFF 0%,#6D5DF6 55%,#7C3AED 100%); color:#fff; border:0; border-radius:999px; padding:11px; font-size:15px; font-weight:600; cursor:pointer; }
button:hover { opacity:0.92; }
.note { color:#475569; font-size:12px; margin:16px 0 0; line-height:1.6; }
</style>
</head>
<body>
<form class="card" method="post" action="/login">
<h1>⚡ CSL-Meter</h1>
<p class="sub">站主登录 · 自托管部署可选启用</p>
__ERROR__
<label for="u">用户名</label>
<input id="u" name="username" autocomplete="username" required/>
<label for="p">口令</label>
<input id="p" name="password" type="password" autocomplete="current-password" required/>
<button type="submit">登录</button>
<p class="note">本站数据全部公开，此登录仅供自托管部署在启用 CSL_GATE_PASSWORD_SHA256 时使用，未配置时本站无任何登录拦截。读数标注规则：标注 Simulated · 模拟生成 的是模拟基线数据，标注 Server-Verified 的是真实探测记录，请按标注区分。</p>
</form>
</body>
</html>"""
    return page.replace("__ERROR__", err_html)

class CSLRequestHandler(BaseHTTPRequestHandler):
    server_version = "CSL-Meter/1.3"

    def log_message(self, fmt, *args):
        return

    def _client_ip(self) -> str:
        xff = self.headers.get("X-Forwarded-For")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0] if self.client_address else "127.0.0.1"

    def _send_headers(self, status: int, content_type: str, cache_sec: int = 0, extra_headers: dict = None):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        self.send_header("Access-Control-Allow-Origin", "*")
        if cache_sec > 0:
            self.send_header("Cache-Control", f"public, max-age={cache_sec}")
        else:
            self.send_header("Cache-Control", "no-store")
        if extra_headers:
            for hk, hv in extra_headers.items():
                self.send_header(hk, hv)
        self.end_headers()

    def _send_json(self, status: int, data: dict, cache_sec: int = 3):
        # Controlled merge (2026-11-06): the overlay's blanket
        # data_status="demo-simulated" stamp is gone; JSON data surfaces now
        # carry the per-origin meta produced by make_data_status_meta /
        # _global_data_status_meta at each endpoint.
        body = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self._send_headers(status, "application/json; charset=utf-8", cache_sec=cache_sec)
        self.wfile.write(body)

    def _send_text(self, status: int, text: str, content_type: str, cache_sec: int = 3600):
        body = text.encode("utf-8")
        self._send_headers(status, content_type, cache_sec=cache_sec)
        self.wfile.write(body)

    def _send_html(self, status: int, html_str: str, allow_iframe: bool = False):
        # Public-data banner (overlay): injected site-wide on every HTML
        # response. Labeling is governed by data_origin, and real verified
        # records must render as Server-Verified.
        html_str = re.sub(r"<body[^>]*>", lambda m: m.group(0) + DEMO_BANNER, html_str, count=1)
        if DEMO_BANNER not in html_str:
            html_str = DEMO_BANNER + html_str
        body = html_str.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("X-Content-Type-Options", "nosniff")
        if not allow_iframe:
            self.send_header("X-Frame-Options", "SAMEORIGIN")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(body)

    def _send_redirect(self, location: str, set_cookie: str = None):
        self.send_response(302)
        self.send_header("Location", location)
        if set_cookie:
            self.send_header("Set-Cookie", set_cookie)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _session_token(self):
        raw = self.headers.get("Cookie", "")
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("csl_session="):
                return part[len("csl_session="):]
        return None

    def _gate_ok(self) -> bool:
        if not GATE_ENABLED:
            return True
        if not self.headers.get("X-Forwarded-For"):
            return True  # direct local request from the host itself (ops only)
        tok = self._session_token()
        if not tok:
            return False
        with _sessions_lock:
            exp = _sessions.get(tok)
            if exp and exp > time.time():
                return True
            _sessions.pop(tok, None)
        return False

    def _require_gate(self, path: str) -> bool:
        if self._gate_ok():
            return True
        if path.startswith("/api") or path.startswith("/v1") or path.endswith(".svg") or path.endswith(".json"):
            self._send_json(401, {"error": "AUTH_REQUIRED", "attribution": make_attribution("/")}, cache_sec=0)
        else:
            self._send_redirect("/login")
        return False

    def _handle_login(self):
        content_len = int(self.headers.get("Content-Length", "0"))
        if content_len <= 0 or content_len > 32768:
            self._send_html(400, render_login_page("请求无效"))
            return
        raw = self.rfile.read(content_len).decode("utf-8", "replace")
        form = urllib.parse.parse_qs(raw)
        user = (form.get("username", [""])[0] or "").strip()
        pw = form.get("password", [""])[0] or ""
        digest = hashlib.sha256(pw.encode("utf-8")).hexdigest()
        if user == GATE_USER and hmac.compare_digest(digest, GATE_PASSWORD_SHA256):
            tok = secrets.token_urlsafe(32)
            with _sessions_lock:
                _sessions[tok] = time.time() + SESSION_TTL_SECONDS
            cookie = "csl_session=" + tok + "; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=" + str(SESSION_TTL_SECONDS)
            self._send_redirect("/", set_cookie=cookie)
        else:
            time.sleep(0.6)
            self._send_html(401, render_login_page("用户名或口令不正确"))

    def _handle_logout(self):
        tok = self._session_token()
        if tok:
            with _sessions_lock:
                _sessions.pop(tok, None)
        cookie = "csl_session=; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=0"
        self._send_redirect("/login", set_cookie=cookie)

    def do_HEAD(self):
        """v1.5.7: HEAD mirrors GET status/headers with an empty body.

        BaseHTTPRequestHandler answers 501 for unimplemented methods.
        Google's sitemap fetcher appears to probe with HEAD first and
        give up on the 501: GSC stayed at "Couldn't fetch" with 0
        discovered pages while a plain GET of /sitemap.xml returned
        200 and Bing fetched it fine (both re-verified 2026-11-08,
        including a delete-and-resubmit cycle in GSC). Run the real
        GET handler with the body sink swapped out, so the HEAD
        response is identical to GET by construction, minus the body.
        (First attempt at this fix sank the headers along with the
        body — both travel over wfile — and closed the connection
        with no response at all; the writer below forwards everything
        up to end_headers() and only then starts discarding.)
        """
        class _HeadWriter:
            """Forward the status line and headers, swallow the body.

            Both go through wfile; end_headers() is the boundary —
            every send path in this handler writes its body only
            after end_headers() has been called.
            """

            def __init__(self, real):
                self._real = real
                self.discard = False

            def write(self, data):
                if self.discard:
                    return len(data)
                return self._real.write(data)

            def flush(self):
                return self._real.flush()

        writer = _HeadWriter(self.wfile)
        real_wfile = self.wfile
        real_end_headers = self.end_headers

        def _end_headers_then_discard():
            real_end_headers()
            writer.discard = True

        self.wfile = writer
        self.end_headers = _end_headers_then_discard
        try:
            self.do_GET()
        finally:
            self.wfile = real_wfile
            self.end_headers = real_end_headers

    def do_GET(self):
        ip = self._client_ip()
        if not rate_limiter.allow(ip, is_write=False):
            self._send_json(429, {"error": "RATE_LIMITED", "attribution": make_attribution("/")}, cache_sec=0)
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/login":
            if self._gate_ok():
                self._send_redirect("/")
            else:
                self._send_html(200, render_login_page())
            return
        if path == "/logout":
            self._handle_logout()
            return

        # GEO kit (v1.5.0): public, no login.
        if path == "/llms.txt":
            self._send_text(200, LLMS_TXT, "text/plain; charset=utf-8")
            return
        if path == "/robots.txt":
            self._send_text(200, ROBOTS_TXT, "text/plain; charset=utf-8")
            return
        if path == "/sitemap.xml":
            self._send_text(200, _sitemap_xml(), "application/xml; charset=utf-8")
            return

        # v1.5.0: the site-wide login wall is gone; every route below is
        # public. The retained login machinery gates nothing here.

        verified_cnt = db.count_verified_reports()
        status_meta = _global_data_status_meta()

        # 1. Health & Metrics Endpoint
        if path in ("/health", "/api/v1/health", "/v1/health"):
            self._send_json(
                200,
                {
                    "status": "ok",
                    "service": BRAND_NAME,
                    "domain": SITE_DOMAIN,
                    "api_domain": API_DOMAIN,
                    "verified_reports_count": verified_cnt,
                    **status_meta,
                    "attribution": make_attribution("/api/v1/health"),
                },
                cache_sec=2,
            )
            return

        # 2. Dynamic SVG Badge for Plan: /badge/plan/{provider}/{plan}.svg
        m_badge_plan = re.match(r"^/badge/plan/([a-z0-9_-]+)/([a-z0-9_-]+)\.svg$", path)
        if m_badge_plan:
            prov, pl = m_badge_plan.group(1), m_badge_plan.group(2)
            plan = db.get_plan(prov, pl)
            if not plan:
                svg = render_svg_badge(f"{prov}/{pl}", 0.0, 0.0, 0.0, 0, is_demo=True)
                self._send_headers(404, "image/svg+xml; charset=utf-8", cache_sec=1)
                self.wfile.write(svg.encode("utf-8"))
                return
            is_demo = plan.get("data_origin") != "Server-Verified"
            svg = render_svg_badge(
                f"{plan['provider_slug']} · {plan['plan_slug']}",
                plan["csl_index_7d"],
                plan["net_jsd"],
                plan["median_tps"],
                plan["sample_count_7d"],
                is_demo=is_demo,
            )
            self._send_headers(200, "image/svg+xml; charset=utf-8", cache_sec=2)
            self.wfile.write(svg.encode("utf-8"))
            return

        # 3. Dynamic SVG Badge for Snapshot Report: /badge/r/{uuid}.svg
        m_badge_rep = re.match(r"^/badge/r/([a-zA-Z0-9_-]+)\.svg$", path)
        if m_badge_rep:
            rid = m_badge_rep.group(1)
            rep = db.get_report(rid)
            if not rep:
                svg = render_svg_badge(f"#{rid} not found", 0.0, 0.0, 0.0, 0, is_demo=True)
                self._send_headers(404, "image/svg+xml; charset=utf-8", cache_sec=1)
                self.wfile.write(svg.encode("utf-8"))
                return
            is_demo = rep.get("data_origin") != "Server-Verified"
            svg = render_svg_badge(
                f"#{rep['uuid']} · {rep['claimed_model']}",
                rep["csl_index"],
                rep["net_jsd"],
                rep["tps"],
                1,
                is_demo=is_demo,
            )
            self._send_headers(200, "image/svg+xml; charset=utf-8", cache_sec=2)
            self.wfile.write(svg.encode("utf-8"))
            return

        # 4. Iframe Embed Card for Plan or Report
        m_embed_plan = re.match(r"^/embed/plan/([a-z0-9_-]+)/([a-z0-9_-]+)$", path)
        if m_embed_plan:
            prov, pl = m_embed_plan.group(1), m_embed_plan.group(2)
            plan = db.get_plan(prov, pl)
            if not plan:
                self._send_html(404, "<html><body>Plan not found</body></html>", allow_iframe=True)
                return
            is_demo = plan.get("data_origin") != "Server-Verified"
            card = render_embed_card(
                f"{plan['provider_name']} · {plan['plan_name']}",
                f"宣称模型: {plan['claimed_model']} | 峰谷 ΔCSL: +{plan['peak_delta_csl']:.1f}",
                plan["csl_index_7d"],
                plan["net_jsd"],
                plan["nearest_profile"],
                plan["median_tps"],
                plan["sample_count_7d"],
                f"{SITE_DOMAIN}/timeline?p1={prov}/{pl}",
                is_demo=is_demo,
            )
            self._send_html(200, card, allow_iframe=True)
            return

        m_embed_rep = re.match(r"^/embed/r/([a-zA-Z0-9_-]+)$", path)
        if m_embed_rep:
            rid = m_embed_rep.group(1)
            rep = db.get_report(rid)
            if not rep:
                self._send_html(404, "<html><body>Report not found</body></html>", allow_iframe=True)
                return
            is_demo = rep.get("data_origin") != "Server-Verified"
            card = render_embed_card(
                f"快照 #{rep['uuid']} · {rep['plan_name']}",
                f"采样时间: {rep['created_at']} | 状态: {rep['verification_mode']}",
                rep["csl_index"],
                rep["net_jsd"],
                rep["nearest_profile"],
                rep["tps"],
                1,
                f"{SITE_DOMAIN}/r/{rep['uuid']}",
                is_demo=is_demo,
            )
            self._send_html(200, card, allow_iframe=True)
            return

        # 5. Open Read-Only JSON APIs
        if path in ("/api/v1/plans", "/v1/plans"):
            cat = qs.get("category", [None])[0]
            only_v = qs.get("origin", ["all"])[0] == "verified"
            plans = db.list_plans(category=cat, only_verified=only_v)
            self._send_json(
                200,
                {
                    **status_meta,
                    "count": len(plans),
                    "plans": plans,
                    "attribution": make_attribution("/"),
                },
                cache_sec=3,
            )
            return

        m_api_plan = re.match(r"^/(?:api/)?v1/plans/([a-z0-9_-]+)/([a-z0-9_-]+)$", path)
        if m_api_plan:
            prov, pl = m_api_plan.group(1), m_api_plan.group(2)
            plan = db.get_plan(prov, pl)
            if not plan:
                self._send_json(404, {"error": "PLAN_NOT_FOUND", "attribution": make_attribution("/")}, cache_sec=1)
                return
            plan_meta = make_data_status_meta(plan.get("data_origin") == "Server-Verified")
            self._send_json(
                200,
                {
                    **plan_meta,
                    "plan": plan,
                    "attribution": make_attribution(
                        f"/timeline?p1={prov}/{pl}",
                        f"/badge/plan/{prov}/{pl}.svg",
                    ),
                },
                cache_sec=3,
            )
            return

        m_api_rep_raw = re.match(r"^/(?:api/)?v1/reports/([a-zA-Z0-9_-]+)(?:/raw\.json)?$", path)
        if m_api_rep_raw:
            rid = m_api_rep_raw.group(1)
            rep = db.get_report(rid)
            if not rep:
                self._send_json(404, {"error": "REPORT_NOT_FOUND", "attribution": make_attribution("/")}, cache_sec=1)
                return
            rep_meta = make_data_status_meta(rep.get("data_origin") == "Server-Verified")
            self._send_json(
                200,
                {
                    **rep_meta,
                    "report": rep,
                    "attribution": make_attribution(f"/r/{rid}", f"/badge/r/{rid}.svg"),
                },
                cache_sec=3,
            )
            return

        if path in ("/api/v1/timeline", "/v1/timeline"):
            prov = qs.get("provider", ["volcengine"])[0]
            pl = qs.get("plan", ["coding-plan-lite"])[0]
            btype = qs.get("bucket_type", ["hourly_24h"])[0]
            series = db.get_timeline(prov, pl, btype)
            self._send_json(
                200,
                {
                    **status_meta,
                    "provider_slug": prov,
                    "plan_slug": pl,
                    "bucket_type": btype,
                    "series": series,
                    "attribution": make_attribution(
                        f"/timeline?p1={prov}/{pl}",
                        f"/badge/plan/{prov}/{pl}.svg",
                    ),
                },
                cache_sec=3,
            )
            return

        # 6. Web Console Views
        if path == "/":
            self._send_html(200, render_home_page(qs))
            return

        if path == "/timeline":
            self._send_html(200, render_timeline_page(qs))
            return


        m_rep_view = re.match(r"^/r/([a-zA-Z0-9_-]+)$", path)
        if m_rep_view:
            rid = m_rep_view.group(1)
            html_page = render_report_page(rid)
            if not html_page:
                self._send_html(404, "<html><body>Snapshot not found</body></html>")
                return
            self._send_html(200, html_page)
            return

        self._send_json(404, {"error": "NOT_FOUND", "attribution": make_attribution("/")}, cache_sec=0)

    def do_POST(self):
        # Overlay order: write rate limit first, then /login, then
        # routing. Since v1.5.0 there is no access gate on POST: the
        # only POST route is the probe submission, public and protected
        # by the Cloudflare Turnstile check below (anti-abuse,
        # fail-closed) instead of a login.
        ip = self._client_ip()
        if not rate_limiter.allow(ip, is_write=True):
            self._send_json(429, {"error": "WRITE_RATE_LIMITED", "attribution": make_attribution("/")}, cache_sec=0)
            return

        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path == "/login":
            self._handle_login()
            return

        if path not in ("/api/v1/probe", "/v1/probe"):
            self._send_json(404, {"error": "NOT_FOUND", "attribution": make_attribution("/")}, cache_sec=0)
            return

        content_len = int(self.headers.get("Content-Length", "0"))
        if content_len <= 0 or content_len > 32768:
            self._send_json(400, {"error": "INVALID_PAYLOAD_SIZE", "attribution": make_attribution("/")}, cache_sec=0)
            return

        raw_bytes = self.rfile.read(content_len)
        try:
            payload = json.loads(raw_bytes.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "MALFORMED_JSON", "attribution": make_attribution("/")}, cache_sec=0)
            return
        finally:
            raw_bytes = None

        # Verify Cloudflare Turnstile token before probing
        ts_token = payload.get("cf_turnstile_response") or payload.get("cf-turnstile-response") or ""
        ts_ok, ts_err = verify_turnstile_token(ts_token, ip)
        if not ts_ok:
            if "api_key" in payload:
                payload["api_key"] = None
            self._send_json(403, {"error": ts_err, "attribution": make_attribution("/")}, cache_sec=0)
            return

        try:
            rep = db.record_probe_submission(payload)
            self._send_json(
                200,
                {
                    "status": "verified",
                    "data_status": "verified-live",
                    "report": rep,
                    "attribution": make_attribution(f"/r/{rep['uuid']}", f"/badge/r/{rep['uuid']}.svg"),
                },
                cache_sec=0,
            )
        except ValueError as ve:
            msg = str(ve)
            if "SSRF_POLICY_BLOCKED" in msg:
                code = 403
            elif "UPSTREAM_PROBE_FAILED" in msg:
                code = 502
            else:
                code = 400
            self._send_json(code, {"error": msg, "attribution": make_attribution("/")}, cache_sec=0)
        finally:
            payload = None


def run_server():
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", "8090"))
    server = ThreadingHTTPServer((host, port), CSLRequestHandler)
    print(f"[CSL-Meter v1.3] Listening on http://{host}:{port} (DB: {DB_PATH})", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    run_server()
