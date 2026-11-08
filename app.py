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
    '<div class="calib-strip" role="region" aria-label="Public data labeling notice">'
    '<div class="calib-strip__inner">'
    '<span class="calib-strip__tag">PUBLIC CALIBRATION</span>'
    '<span class="calib-strip__text">CSL-Meter Public Observatory — '
    + DEMO_NOTICE_EN
    + " (konspace.cc)</span>"
    "</div></div>"
)

FONT_LATIN_WOFF2_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "assets",
    "fonts",
    "csl-sans-latin.woff2",
)
try:
    with open(FONT_LATIN_WOFF2_PATH, "rb") as _font_fh:
        _FONT_LATIN_WOFF2_BYTES = _font_fh.read()
except OSError:
    _FONT_LATIN_WOFF2_BYTES = b""

BRAND_MARK_SVG = (
    '<svg class="brand-mark-svg" width="16" height="16" viewBox="0 0 16 16" '
    'fill="none" aria-hidden="true">'
    '<rect x="1.25" y="1.25" width="13.5" height="13.5" rx="2" stroke="currentColor" stroke-width="1.4"/>'
    '<path d="M3.5 10.5L6.3 7.2L8.8 9.2L12.5 4.8" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>'
    '<circle cx="12.5" cy="4.8" r="1.4" fill="currentColor"/>'
    "</svg>"
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
        return False, "TURNSTILE_SECRET_NOT_CONFIGURED: the server has no Turnstile secret configured; submission rejected."

    if not token or not str(token).strip():
        return False, "TURNSTILE_TOKEN_MISSING: please complete the Cloudflare Turnstile check on the page first."

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
        return False, f"TURNSTILE_VERIFY_FAILED: human verification failed ({err_codes})."
    except Exception as exc:
        return False, f"TURNSTILE_VERIFY_ERROR: verification service communication error ({type(exc).__name__})."


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
            "data_notice": "Contains Server-Verified samples generated by real upstream API probes.",
        }
    return {
        "data_status": "demo-simulated",
        "data_notice": "Currently showing initial demo baselines (Simulated · 模拟生成); submit a real API key to generate Server-Verified probe records.",
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
@font-face {
  font-family: 'CSL Instrument Sans';
  src: url('/assets/fonts/csl-sans-latin.woff2') format('woff2');
  font-weight: 400 700;
  font-style: normal;
  font-display: swap;
  ascent-override: 96%;
  descent-override: 24%;
}
:root {
  --bg-canvas: #F4F6F9;
  --bg-surface: #FFFFFF;
  --bg-subtle: #EEF2F7;
  --bg-elevated: #EEF2F7;
  --border-hairline: #DCE3EC;
  --border-subtle: #DCE3EC;
  --border-strong: #B8C4D4;
  --border-focus: #0F52BA;
  --text-primary: #142033;
  --text-body: #24344D;
  --text-muted: #4B5E78;
  --accent: #0F52BA;
  --accent-blue: #0F52BA;
  --accent-bright: #0F52BA;
  --accent-hover: #0B3F91;
  --accent-soft: #E8F0FE;
  --accent-dim: #E8F0FE;
  --accent-border: #93B8F8;
  --status-sim-fg: #8A4308;
  --status-sim-bg: #FFF7EB;
  --status-sim-bd: #F3C68F;
  --status-ver-fg: #0F5E36;
  --status-ver-bg: #ECF9F2;
  --status-ver-bd: #8AD5B0;
  --status-err-fg: #A61B1B;
  --status-err-bg: #FDF2F2;
  --status-err-bd: #F5B7B7;
  --chart-grid: #DCE3EC;
  --chart-ref: #64748B;
  --sp-1: 4px;
  --sp-2: 8px;
  --sp-3: 12px;
  --sp-4: 16px;
  --sp-5: 20px;
  --sp-6: 24px;
  --sp-8: 32px;
  --sp-10: 40px;
  --shell-max: 1380px;
  --radius-xs: 3px;
  --radius-sm: 6px;
  --radius-md: 8px;
  --radius-card: 8px;
  --shadow-panel: 0 1px 2px rgba(20, 32, 51, 0.04);
  --shadow-focus: 0 0 0 3px rgba(15, 82, 186, 0.18);
  --fs-hero: clamp(1.75rem, 2.2vw, 2.25rem);
  --fs-h1: clamp(1.1875rem, 1.5vw, 1.375rem);
  --fs-h2: 0.9375rem;
  --fs-body: 0.875rem;
  --fs-table: 0.8125rem;
  --fs-sm: 0.75rem;
  --fs-xs: 0.6875rem;
  --dur-fast: 150ms;
  --dur-base: 220ms;
  --dur-slow: 280ms;
  --ease-out: cubic-bezier(0.22, 1, 0.36, 1);
  --ease-in-out: cubic-bezier(0.4, 0, 0.2, 1);
  --font-sans: 'CSL Instrument Sans', -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Hiragino Sans GB', 'HarmonyOS Sans SC', 'Microsoft YaHei UI', 'Microsoft YaHei', 'Noto Sans CJK SC', 'Source Han Sans SC', system-ui, sans-serif;
  --font-mono: ui-monospace, 'SFMono-Regular', 'SF Mono', Menlo, Monaco, Consolas, 'Liberation Mono', 'Noto Sans Mono CJK SC', monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg-canvas: #0E1520;
    --bg-surface: #162030;
    --bg-subtle: #1C293D;
    --bg-elevated: #1C293D;
    --border-hairline: #26354B;
    --border-subtle: #26354B;
    --border-strong: #384D6B;
    --border-focus: #4D8EFF;
    --text-primary: #E6ECF5;
    --text-body: #C5D1E0;
    --text-muted: #8E9FB7;
    --accent: #4D8EFF;
    --accent-blue: #4D8EFF;
    --accent-bright: #4D8EFF;
    --accent-hover: #6BA1FF;
    --accent-soft: rgba(77, 142, 255, 0.16);
    --accent-dim: rgba(77, 142, 255, 0.16);
    --accent-border: rgba(77, 142, 255, 0.44);
    --status-sim-fg: #F7B955;
    --status-sim-bg: #291E0E;
    --status-sim-bd: #664614;
    --status-ver-fg: #3DD68C;
    --status-ver-bg: #0F291E;
    --status-ver-bd: #1E5C3E;
    --status-err-fg: #FF6B6B;
    --status-err-bg: #2D1418;
    --status-err-bd: #6E262E;
    --chart-grid: #26354B;
    --chart-ref: #8E9FB7;
    --shadow-panel: 0 1px 3px rgba(6, 10, 18, 0.35);
    --shadow-focus: 0 0 0 3px rgba(77, 142, 255, 0.25);
  }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after {
    animation-duration: 0.01ms !important;
    animation-iteration-count: 1 !important;
    transition-duration: 0.01ms !important;
    scroll-behavior: auto !important;
  }
}
* { box-sizing: border-box; margin: 0; padding: 0; }
html, body {
  background-color: var(--bg-canvas);
  color: var(--text-body);
  font-family: var(--font-sans);
  font-size: 14px;
  line-height: 1.5;
  -webkit-font-smoothing: antialiased;
  text-rendering: optimizeLegibility;
}
a {
  color: var(--accent);
  text-decoration: none;
  transition: color var(--dur-fast) var(--ease-out);
}
a:hover { color: var(--accent-hover); text-decoration: underline; }
a:focus-visible, button:focus-visible, input:focus-visible, select:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  box-shadow: var(--shadow-focus);
}
.mono, .num {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums slashed-zero;
  font-feature-settings: "tnum" 1, "zero" 1;
}
.tnum {
  font-variant-numeric: tabular-nums slashed-zero;
  font-feature-settings: "tnum" 1, "zero" 1;
}
.calib-strip {
  background: var(--status-sim-bg);
  border-bottom: 1px solid var(--status-sim-bd);
  color: var(--status-sim-fg);
  font-size: var(--fs-sm);
  line-height: 1.45;
}
.calib-strip__inner {
  max-width: var(--shell-max);
  margin: 0 auto;
  padding: var(--sp-2) var(--sp-5);
  display: flex;
  align-items: center;
  gap: var(--sp-2);
}
.calib-strip__tag {
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  font-weight: 700;
  letter-spacing: 0.04em;
  padding: 2px 6px;
  border-radius: var(--radius-xs);
  border: 1px solid var(--status-sim-bd);
  background: var(--bg-surface);
  color: var(--status-sim-fg);
  white-space: nowrap;
  flex-shrink: 0;
}
.calib-strip__text {
  font-weight: 500;
}
.shell {
  max-width: var(--shell-max);
  margin: 0 auto;
  padding: 0 var(--sp-5) var(--sp-10);
}
.topbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  flex-wrap: wrap;
  gap: var(--sp-3);
  padding: var(--sp-4) 0;
  border-bottom: 1px solid var(--border-hairline);
  margin-bottom: var(--sp-4);
}
.brand-wrap {
  display: flex;
  align-items: center;
  gap: var(--sp-3);
  min-width: 0;
}
.brand-badge {
  display: inline-flex;
  align-items: center;
  gap: var(--sp-2);
  background: var(--text-primary);
  border: 1px solid var(--text-primary);
  color: var(--bg-surface);
  font-family: var(--font-mono);
  font-weight: 700;
  font-size: var(--fs-sm);
  letter-spacing: 0.01em;
  padding: 6px 14px;
  border-radius: 999px;
  white-space: nowrap;
  flex-shrink: 0;
  transition: background var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out);
}
.brand-badge:hover {
  background: var(--accent);
  border-color: var(--accent);
  color: #FFFFFF;
  text-decoration: none;
}
.brand-mark-svg { flex-shrink: 0; }
.brand-title {
  color: var(--text-primary);
  font-weight: 700;
  font-size: var(--fs-body);
  letter-spacing: -0.01em;
  line-height: 1.3;
}
.brand-sub {
  color: var(--text-muted);
  font-size: var(--fs-xs);
  line-height: 1.35;
}
.nav-links {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 2px;
  background: var(--bg-subtle);
  border: 1px solid var(--border-hairline);
  padding: 4px;
  border-radius: 999px;
}
.nav-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 14px;
  border-radius: 999px;
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--text-body);
  background: transparent;
  border: 1px solid transparent;
  cursor: pointer;
  white-space: nowrap;
  transition: background var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out);
}
.nav-btn:hover {
  color: var(--accent);
  background: var(--bg-surface);
  text-decoration: none;
}
.nav-btn.active {
  color: var(--bg-surface);
  background: var(--text-primary);
  border-color: var(--text-primary);
  text-decoration: none;
}
.btn-action {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 5px 10px;
  border-radius: var(--radius-sm);
  font-size: var(--fs-xs);
  font-weight: 600;
  font-family: var(--font-mono);
  color: var(--text-body);
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  cursor: pointer;
  white-space: nowrap;
  transition: background var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out);
}
.btn-action:hover {
  border-color: var(--accent);
  color: var(--accent);
  background: var(--accent-soft);
  text-decoration: none;
}
/* Artificial Analysis Inspired Hero, Triptych & Pareto Deck */
.aa-hero {
  display: grid;
  grid-template-columns: minmax(0, 1.45fr) minmax(0, 1fr);
  gap: var(--sp-6);
  align-items: start;
  padding: var(--sp-2) 0 var(--sp-5);
  margin-bottom: var(--sp-3);
  border-bottom: 1px solid var(--border-hairline);
}
.aa-hero__left {
  display: flex;
  flex-direction: column;
  gap: var(--sp-2);
}
.aa-hero__kicker {
  display: inline-flex;
  align-items: center;
  gap: var(--sp-2);
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  font-weight: 600;
  color: var(--accent);
  letter-spacing: 0.05em;
  text-transform: uppercase;
}
.aa-hero__title {
  font-size: clamp(28px, 3.1vw, 40px);
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.1;
  letter-spacing: -0.032em;
  margin: 0;
}
.aa-hero__zh {
  font-size: var(--fs-h1);
  font-weight: 700;
  color: var(--text-body);
  line-height: 1.3;
  letter-spacing: -0.015em;
}
.aa-hero__lead {
  font-size: var(--fs-body);
  color: var(--text-muted);
  line-height: 1.55;
  max-width: 68ch;
}
.aa-hero__stats {
  display: flex;
  flex-wrap: wrap;
  gap: var(--sp-4);
  margin-top: var(--sp-2);
  padding-top: var(--sp-3);
  border-top: 1px solid var(--border-hairline);
}
.aa-stat-pill {
  display: flex;
  flex-direction: column;
  gap: 1px;
}
.aa-stat-pill__lbl {
  font-size: var(--fs-xs);
  color: var(--text-muted);
}
.aa-stat-pill__num {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: 22px;
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.15;
}
.aa-ledger {
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-panel);
  overflow: hidden;
}
.aa-ledger__item {
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: var(--sp-3);
  padding: var(--sp-3) var(--sp-4);
  border-bottom: 1px solid var(--border-hairline);
  transition: background var(--dur-fast) var(--ease-out);
}
.aa-ledger__item:last-child { border-bottom: 0; }
.aa-ledger__item:hover { background: var(--bg-subtle); text-decoration: none; }
.aa-ledger__kicker {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--accent);
  margin-bottom: 2px;
}
.aa-ledger__title {
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--text-primary);
  line-height: 1.38;
}
.aa-ledger__arrow {
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  color: var(--text-muted);
  background: var(--bg-subtle);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-xs);
  width: 22px;
  height: 22px;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  flex-shrink: 0;
}
.aa-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-3);
  flex-wrap: wrap;
  margin-bottom: var(--sp-4);
}
.aa-pill-group {
  display: inline-flex;
  align-items: center;
  flex-wrap: wrap;
  gap: 3px;
  background: var(--bg-subtle);
  border: 1px solid var(--border-hairline);
  padding: 4px;
  border-radius: 999px;
}
.aa-pill {
  padding: 5px 14px;
  border-radius: 999px;
  font-size: var(--fs-xs);
  font-weight: 600;
  color: var(--text-body);
  text-decoration: none;
  transition: background var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out);
}
.aa-pill:hover {
  color: var(--text-primary);
  background: var(--bg-surface);
  text-decoration: none;
}
.aa-pill.active {
  background: var(--text-primary);
  color: var(--bg-surface);
}
.aa-triptych {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--sp-4);
  margin-bottom: var(--sp-4);
}
.aa-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  padding: var(--sp-4);
  box-shadow: var(--shadow-panel);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: var(--sp-3);
}
.aa-card__head {
  display: flex;
  flex-direction: column;
  gap: 4px;
}
.aa-card__title {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  font-size: var(--fs-h2);
  font-weight: 700;
  color: var(--text-primary);
}
.aa-sq {
  width: 10px;
  height: 10px;
  border-radius: 2px;
  flex-shrink: 0;
}
.aa-sq--cobalt { background: var(--accent); }
.aa-sq--amber { background: var(--status-sim-fg); }
.aa-sq--emerald { background: var(--status-ver-fg); }
.aa-sq--crimson { background: var(--status-err-fg); }
.aa-card__sub {
  font-size: var(--fs-xs);
  color: var(--text-muted);
  line-height: 1.4;
}
.aa-card__prov {
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
  display: flex;
  align-items: center;
  gap: 5px;
}
.aa-bars {
  display: flex;
  flex-direction: column;
  gap: 7px;
  padding: var(--sp-2) 0;
  border-top: 1px solid var(--border-hairline);
  border-bottom: 1px solid var(--border-hairline);
}
.aa-bar-row {
  display: grid;
  grid-template-columns: 122px minmax(0, 1fr) 54px;
  align-items: center;
  gap: var(--sp-2);
  font-size: var(--fs-xs);
}
.aa-bar-lbl {
  color: var(--text-body);
  font-weight: 500;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.aa-bar-track {
  height: 9px;
  background: var(--bg-subtle);
  border-radius: 2px;
  overflow: hidden;
}
.aa-bar-fill {
  height: 100%;
  border-radius: 2px;
}
.aa-bar-val {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-weight: 700;
  color: var(--text-primary);
  text-align: right;
}
.aa-card__foot {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-family: var(--font-mono);
  font-size: 11px;
  color: var(--text-muted);
}
.aa-pareto-legend {
  display: flex;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--sp-4);
  padding: var(--sp-2) var(--sp-4);
  border-bottom: 1px solid var(--border-hairline);
  font-size: var(--fs-xs);
  color: var(--text-body);
  background: var(--bg-surface);
}
.aa-legend-item {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
/* Embroidered Running Hippo Patch (Kbar / recent.design homage) */
.emb-card {
  background: #F2EFE6;
  border: 1px solid #D8D1C1;
  border-radius: 10px;
  box-shadow: 0 10px 28px rgba(20, 32, 51, 0.10), 0 1px 3px rgba(20, 32, 51, 0.06), inset 0 0 32px rgba(160, 146, 120, 0.18);
  padding: 10px;
  max-width: 336px;
  width: 100%;
  justify-self: end;
  position: relative;
  overflow: hidden;
}
.emb-svg {
  width: 100%;
  height: auto;
  display: block;
  border-radius: 6px;
}
.emb-frame { opacity: 0; }
.emb-f1 { animation: embStep1 0.56s steps(1, end) infinite; opacity: 1; }
.emb-f2 { animation: embStep2 0.56s steps(1, end) infinite; }
.emb-f3 { animation: embStep3 0.56s steps(1, end) infinite; }
.emb-f4 { animation: embStep4 0.56s steps(1, end) infinite; }
@keyframes embStep1 { 0%, 24.9% { opacity: 1; } 25%, 100% { opacity: 0; } }
@keyframes embStep2 { 0%, 24.9% { opacity: 0; } 25%, 49.9% { opacity: 1; } 50%, 100% { opacity: 0; } }
@keyframes embStep3 { 0%, 49.9% { opacity: 0; } 50%, 74.9% { opacity: 1; } 75%, 100% { opacity: 0; } }
@keyframes embStep4 { 0%, 74.9% { opacity: 0; } 75%, 100% { opacity: 1; } }
@media (prefers-reduced-motion: reduce) {
  .emb-f1 { animation: none !important; opacity: 1 !important; }
  .emb-f2, .emb-f3, .emb-f4 { animation: none !important; opacity: 0 !important; }
}
/* Observatory Command Deck (Home Hero) */
.obs-deck {
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  box-shadow: var(--shadow-panel);
  margin-bottom: var(--sp-4);
  overflow: hidden;
}
.obs-deck__top {
  display: grid;
  grid-template-columns: minmax(0, 1.65fr) minmax(0, 1fr);
  border-bottom: 1px solid var(--border-hairline);
}
.obs-hero-main {
  padding: var(--sp-4) var(--sp-5);
  border-right: 1px solid var(--border-hairline);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: var(--sp-3);
}
.obs-eyebrow {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: var(--sp-2);
  flex-wrap: wrap;
}
.obs-eyebrow__tag {
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  font-weight: 600;
  color: var(--text-muted);
  letter-spacing: 0.04em;
  text-transform: uppercase;
}
.obs-metrics-row {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--sp-4);
  padding: var(--sp-2) 0;
  border-top: 1px solid var(--border-hairline);
  border-bottom: 1px solid var(--border-hairline);
}
.obs-stat__label {
  font-size: var(--fs-xs);
  color: var(--text-muted);
  font-weight: 500;
  margin-bottom: 2px;
}
.obs-stat__val {
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  font-size: var(--fs-hero);
  font-weight: 700;
  color: var(--text-primary);
  line-height: 1.1;
  letter-spacing: -0.02em;
}
.obs-stat__val--accent { color: var(--accent); }
.obs-stat__sub {
  font-size: var(--fs-xs);
  color: var(--text-muted);
  margin-top: 3px;
  white-space: nowrap;
  overflow: hidden;
  text-overflow: ellipsis;
}
.obs-spectrum {
  display: flex;
  flex-direction: column;
  gap: var(--sp-1);
}
.obs-spectrum__head {
  display: flex;
  justify-content: space-between;
  align-items: center;
  font-size: var(--fs-xs);
  color: var(--text-muted);
  gap: var(--sp-2);
  flex-wrap: wrap;
}
.obs-spectrum__bars {
  display: grid;
  grid-template-columns: repeat(15, minmax(0, 1fr));
  gap: 4px;
  align-items: end;
  height: 44px;
  padding: 6px 8px 4px;
  background: var(--bg-subtle);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-xs);
  position: relative;
}
.spec-col {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: flex-end;
  height: 100%;
  gap: 2px;
  min-width: 0;
}
.spec-bar {
  width: 100%;
  background: var(--accent);
  border-radius: 1.5px 1.5px 0 0;
  transition: opacity var(--dur-fast) var(--ease-out);
}
.spec-bar--warn {
  background: var(--status-err-fg);
}
.spec-col:hover .spec-bar { opacity: 0.78; }
.obs-hero-side {
  padding: var(--sp-4) var(--sp-5);
  background: var(--bg-subtle);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: var(--sp-3);
}
.kpi-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  gap: var(--sp-3);
  margin-bottom: var(--sp-4);
}
.kpi-grid-2x2 {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: var(--sp-2);
}
.kpi-card {
  background: var(--bg-surface);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-sm);
  padding: var(--sp-3) var(--sp-4);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
}
.kpi-label {
  color: var(--text-muted);
  font-size: var(--fs-xs);
  font-weight: 600;
  letter-spacing: 0.02em;
  margin-bottom: var(--sp-1);
}
.kpi-val {
  color: var(--text-primary);
  font-size: 20px;
  font-weight: 700;
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums;
  line-height: 1.2;
}
.kpi-foot {
  color: var(--text-muted);
  font-size: var(--fs-xs);
  margin-top: var(--sp-1);
  line-height: 1.35;
}
/* Panels & Tables */
.panel {
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  margin-bottom: var(--sp-4);
  overflow: hidden;
  box-shadow: var(--shadow-panel);
}
.panel-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--sp-3) var(--sp-4);
  background: var(--bg-subtle);
  border-bottom: 1px solid var(--border-hairline);
  flex-wrap: wrap;
  gap: var(--sp-2);
}
.panel-title {
  color: var(--text-primary);
  font-weight: 700;
  font-size: var(--fs-h2);
  display: flex;
  align-items: center;
  gap: var(--sp-2);
}
.panel-eyebrow {
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  font-weight: 700;
  color: var(--accent);
  background: var(--accent-soft);
  border: 1px solid var(--accent-border);
  padding: 1px 6px;
  border-radius: var(--radius-xs);
}
.filter-bar {
  display: flex;
  align-items: center;
  gap: var(--sp-2);
  flex-wrap: wrap;
}
.seg-group {
  display: inline-flex;
  align-items: center;
  background: var(--bg-surface);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-sm);
  padding: 2px;
  gap: 2px;
  flex-wrap: wrap;
}
.tab-pill {
  padding: 4px 10px;
  border-radius: var(--radius-xs);
  font-size: var(--fs-sm);
  font-weight: 600;
  color: var(--text-muted);
  background: transparent;
  border: 1px solid transparent;
  white-space: nowrap;
  transition: background var(--dur-fast) var(--ease-out), color var(--dur-fast) var(--ease-out);
}
.tab-pill:hover {
  color: var(--text-primary);
  background: var(--bg-subtle);
  text-decoration: none;
}
.tab-pill.active {
  color: #FFFFFF;
  background: var(--accent);
  border-color: var(--accent);
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
  font-variant-numeric: tabular-nums;
}
table.data-table th {
  background: var(--bg-subtle);
  color: var(--text-muted);
  font-weight: 600;
  font-size: var(--fs-sm);
  padding: var(--sp-2) var(--sp-2);
  border-bottom: 1px solid var(--border-strong);
  white-space: nowrap;
}
table.data-table th a {
  color: var(--text-muted);
  display: inline-flex;
  align-items: center;
  gap: 3px;
}
table.data-table th a.sorted {
  color: var(--accent);
  font-weight: 700;
}
table.data-table th a:hover {
  color: var(--accent);
  text-decoration: none;
}
table.data-table td {
  padding: var(--sp-2) var(--sp-2);
  border-bottom: 1px solid var(--border-hairline);
  color: var(--text-body);
  font-size: var(--fs-table);
  white-space: nowrap;
  vertical-align: middle;
  transition: background-color var(--dur-fast) var(--ease-out);
}
table.data-table tbody tr:hover td {
  background-color: var(--accent-soft);
}
table.data-table td.num, table.data-table th.num {
  text-align: right;
  font-family: var(--font-mono);
  font-variant-numeric: tabular-nums slashed-zero;
  font-feature-settings: "tnum" 1, "zero" 1;
}
.csl-bar-wrap {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  justify-content: flex-end;
}
.csl-bar-bg {
  width: 44px;
  height: 7px;
  background: var(--bg-subtle);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-xs);
  overflow: hidden;
  position: relative;
  flex-shrink: 0;
}
.csl-bar-bg::after {
  content: "";
  position: absolute;
  left: 54%;
  top: 0;
  bottom: 0;
  width: 1px;
  background: var(--border-strong);
}
.csl-bar-fill {
  height: 100%;
  background: var(--accent);
}
.csl-bar-fill--warn {
  background: var(--status-err-fg);
}
.delta-pill {
  display: inline-flex;
  align-items: center;
  gap: 5px;
  justify-content: flex-end;
}
.delta-track {
  width: 24px;
  height: 5px;
  background: var(--bg-subtle);
  border-radius: 2px;
  overflow: hidden;
  border: 1px solid var(--border-hairline);
}
.delta-fill {
  height: 100%;
  background: var(--accent);
}
.delta-fill--high { background: var(--status-err-fg); }
.harness-key {
  display: inline-block;
  padding: 1px 5px;
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  color: var(--text-muted);
  background: var(--bg-subtle);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-xs);
}
/* Provider / plan cell: full name wraps to two lines, no ellipsis (all screens). */
table.data-table td.provider-cell { white-space: normal; max-width: 192px; }
table.data-table td.provider-cell .plan-name {
  white-space: normal;
  word-break: break-word;
  line-height: 1.32;
}
@media (min-width: 721px) {
  /* Desktop table density (v1.5.6 contract): fit both home tables in the 1380px shell
     without horizontal scroll; mobile (<=720px) uses scrollable wrapper. */
  table.data-table th { padding: 8px 5px; font-size: 11px; }
  table.data-table td { padding: 7px 5px; font-size: 12px; }
  table.data-table td.tput-cell { line-height: 1.3; }
  table.data-table td.tput-cell .tput-sub {
    font-size: 10.5px; color: var(--text-muted);
  }
  .csl-bar-bg { width: 38px; }
  .csl-bar-wrap { gap: 5px; }
}
.tag-chip {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  padding: 2px 7px;
  border-radius: var(--radius-xs);
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  font-weight: 600;
  color: var(--accent);
  background: var(--accent-soft);
  border: 1px solid var(--accent-border);
  white-space: nowrap;
}
.tag-simulated {
  color: var(--status-sim-fg);
  background: var(--status-sim-bg);
  border: 1px solid var(--status-sim-bd);
}
.tag-verified {
  color: var(--status-ver-fg);
  background: var(--status-ver-bg);
  border: 1px solid var(--status-ver-bd);
}
/* Probe Telemetry Bench */
.probe-bench {
  background: var(--bg-surface);
}
.probe-bench__head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: var(--sp-2) var(--sp-5);
  background: var(--bg-subtle);
  border-bottom: 1px solid var(--border-hairline);
  flex-wrap: wrap;
  gap: var(--sp-2);
}
.probe-grid {
  display: grid;
  grid-template-columns: 2fr 1.15fr 1.15fr 1.25fr auto;
  gap: var(--sp-3);
  padding: var(--sp-3) var(--sp-5);
  align-items: end;
}
.field-group {
  display: flex;
  flex-direction: column;
  gap: var(--sp-1);
  min-width: 0;
}
.field-label {
  font-size: var(--fs-xs);
  color: var(--text-muted);
  font-weight: 600;
  display: flex;
  align-items: center;
  gap: 5px;
}
.step-num {
  font-family: var(--font-mono);
  font-size: 10px;
  font-weight: 700;
  color: var(--accent);
  background: var(--accent-soft);
  border: 1px solid var(--accent-border);
  padding: 0 4px;
  border-radius: 2px;
}
.field-input, .field-select {
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  color: var(--text-primary);
  height: 36px;
  padding: 0 var(--sp-3);
  border-radius: var(--radius-sm);
  font-size: var(--fs-table);
  font-family: var(--font-mono);
  width: 100%;
  transition: border-color var(--dur-fast) var(--ease-out), box-shadow var(--dur-fast) var(--ease-out);
}
.field-input:focus, .field-select:focus {
  outline: none;
  border-color: var(--accent);
  box-shadow: var(--shadow-focus);
}
.turnstile-slot {
  min-height: 36px;
  display: flex;
  align-items: center;
  padding: 0 var(--sp-2);
  border: 1px dashed var(--border-strong);
  border-radius: var(--radius-sm);
  background: var(--bg-subtle);
  font-size: var(--fs-xs);
  color: var(--text-muted);
}
.btn-submit {
  background: var(--accent);
  color: #FFFFFF;
  border: 1px solid var(--accent);
  height: 36px;
  padding: 0 var(--sp-4);
  border-radius: var(--radius-sm);
  font-weight: 600;
  font-size: var(--fs-table);
  cursor: pointer;
  font-family: var(--font-sans);
  white-space: nowrap;
  transition: background var(--dur-fast) var(--ease-out), border-color var(--dur-fast) var(--ease-out);
}
.btn-submit:hover {
  background: var(--accent-hover);
  border-color: var(--accent-hover);
}
.btn-submit:disabled {
  opacity: 0.6;
  cursor: not-allowed;
}
.notice-bar {
  padding: var(--sp-2) var(--sp-4);
  background: var(--bg-subtle);
  border-top: 1px solid var(--border-hairline);
  color: var(--text-muted);
  font-size: var(--fs-sm);
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: var(--sp-2);
}
.notice-bar img {
  max-width: 100%;
  height: auto;
}
.grid-2 {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(0, 1fr);
  gap: var(--sp-4);
}
.citation-grid {
  padding: var(--sp-4);
  display: grid;
  grid-template-columns: minmax(0, 1.08fr) minmax(0, 0.92fr);
  gap: var(--sp-4);
}
.code-box {
  background: var(--bg-subtle);
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-sm);
  padding: var(--sp-3);
  font-family: var(--font-mono);
  font-size: var(--fs-xs);
  color: var(--text-body);
  overflow-x: auto;
  white-space: pre-wrap;
  word-break: break-all;
  line-height: 1.5;
}
.dist-row {
  display: grid;
  grid-template-columns: 52px minmax(0, 1fr) 136px;
  align-items: center;
  gap: var(--sp-2);
  padding: 7px 0;
  border-bottom: 1px solid var(--border-hairline);
}
.dual-bar-track {
  display: flex;
  flex-direction: column;
  gap: 3px;
  background: var(--bg-subtle);
  padding: 3px 4px;
  border-radius: var(--radius-xs);
}
.bar-obs {
  height: 6px;
  background: var(--accent);
  border-radius: 1.5px;
  min-width: 2px;
}
.bar-ref {
  height: 6px;
  background: var(--border-strong);
  border-radius: 1.5px;
  min-width: 2px;
}
/* Timeline summary & heatmap grid */
.tl-summary-strip {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  border-bottom: 1px solid var(--border-hairline);
  background: var(--bg-subtle);
}
.tl-summary-cell {
  padding: var(--sp-3) var(--sp-4);
  border-right: 1px solid var(--border-hairline);
}
.tl-summary-cell:last-child { border-right: 0; }
.heat-grid-24 {
  display: grid;
  grid-template-columns: repeat(12, minmax(0, 1fr));
  gap: 6px;
}
.heat-grid-30 {
  display: grid;
  grid-template-columns: repeat(10, minmax(0, 1fr));
  gap: 6px;
}
.heat-cell {
  border: 1px solid var(--border-hairline);
  border-radius: var(--radius-xs);
  padding: 6px 4px;
  text-align: center;
  background: var(--bg-subtle);
}
.heat-cell--peak {
  border-color: var(--accent-border);
}
/* Report Forensic Header */
.forensic-deck {
  display: grid;
  grid-template-columns: 1.15fr 1.35fr 1.1fr;
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  margin-bottom: var(--sp-4);
  overflow: hidden;
  box-shadow: var(--shadow-panel);
}
.forensic-col {
  padding: var(--sp-4) var(--sp-5);
  border-right: 1px solid var(--border-hairline);
  display: flex;
  flex-direction: column;
  justify-content: space-between;
  gap: var(--sp-2);
}
.forensic-col:last-child { border-right: 0; background: var(--bg-subtle); }
.telemetry-mini-grid {
  display: grid;
  grid-template-columns: repeat(3, minmax(0, 1fr));
  gap: var(--sp-2);
  padding-top: var(--sp-2);
  border-top: 1px solid var(--border-hairline);
}
.footer {
  margin-top: var(--sp-6);
  padding-top: var(--sp-4);
  border-top: 1px solid var(--border-hairline);
  display: flex;
  justify-content: space-between;
  color: var(--text-muted);
  font-size: var(--fs-sm);
  flex-wrap: wrap;
  gap: var(--sp-2);
}
@media (max-width: 980px) {
  .aa-hero { grid-template-columns: minmax(0, 1fr); gap: var(--sp-4); }
  .aa-triptych { grid-template-columns: minmax(0, 1fr); }
  .obs-deck__top { grid-template-columns: minmax(0, 1fr); }
  .obs-hero-main { border-right: 0; border-bottom: 1px solid var(--border-hairline); }
  .probe-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .forensic-deck { grid-template-columns: minmax(0, 1fr); }
  .forensic-col { border-right: 0; border-bottom: 1px solid var(--border-hairline); }
  .tl-summary-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .heat-grid-24 { grid-template-columns: repeat(6, minmax(0, 1fr)); }
  .heat-grid-30 { grid-template-columns: repeat(6, minmax(0, 1fr)); }
  .citation-grid { grid-template-columns: minmax(0, 1fr); }
}
@media (max-width: 720px) {
  .calib-strip__inner { padding: var(--sp-2) var(--sp-3); flex-direction: column; align-items: flex-start; gap: 4px; }
  .shell { padding: 0 var(--sp-3) var(--sp-8); }
  .topbar { padding: var(--sp-3) 0; margin-bottom: var(--sp-3); }
  .aa-hero { padding: var(--sp-1) 0 var(--sp-3); }
  .aa-hero__stats { gap: var(--sp-3); }
  .aa-bar-row { grid-template-columns: 108px minmax(0, 1fr) 48px; }
  .obs-hero-main, .obs-hero-side { padding: var(--sp-3); }
  .obs-metrics-row { grid-template-columns: minmax(0, 1fr); gap: var(--sp-2); }
  .kpi-strip { grid-template-columns: repeat(2, minmax(0, 1fr)); gap: var(--sp-2); }
  .probe-grid { grid-template-columns: minmax(0, 1fr); padding: var(--sp-3); }
  .probe-bench__head { padding: var(--sp-2) var(--sp-3); }
  .grid-2 { grid-template-columns: minmax(0, 1fr); }
  .panel-head { padding: var(--sp-3); }
  .heat-grid-24 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
  .heat-grid-30 { grid-template-columns: repeat(5, minmax(0, 1fr)); }
  .dist-row { grid-template-columns: 44px minmax(0, 1fr) 114px; }
}
@media (max-width: 480px) {
  .kpi-strip, .kpi-grid-2x2, .tl-summary-strip { grid-template-columns: minmax(0, 1fr); }
  .nav-links, .aa-pill-group { width: 100%; justify-content: flex-start; border-radius: var(--radius-md); }
  .nav-btn, .aa-pill { padding: 5px 8px; font-size: var(--fs-xs); }
}
"""


def render_header(active_nav: str = "table") -> str:
    return f"""
    <header class="topbar">
      <div class="brand-wrap">
        <a href="/" class="brand-badge">{BRAND_MARK_SVG}<span>CSL-Meter</span></a>
        <div>
          <div class="brand-title">CSL-Meter · Independent Model Consistency Observatory</div>
          <div class="brand-sub">Consistency, Substitution &amp; Latency (<span class="mono">konspace.cc</span>)</div>
        </div>
      </div>
      <nav class="nav-links" aria-label="Main navigation">
        <a href="/" class="nav-btn {'active' if active_nav == 'table' else ''}">Plans & Providers</a>
        <a href="/timeline" class="nav-btn {'active' if active_nav == 'timeline' else ''}">24h Peaks & 30d Trends</a>
        <a href="/r/a49d2e" class="nav-btn {'active' if active_nav == 'report' else ''}">Probe Snapshot (#a49d2e)</a>
        <a href="/#probe-panel" class="nav-btn">Live Probe</a>
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
    all_plans = db.list_plans()
    recent_reports = db.list_recent_reports(limit=6, only_verified=only_verified)
    verified_total = db.count_verified_reports()
    site_key = os.environ.get("TURNSTILE_SITE_KEY", "").strip()

    # Observatory hero aggregate telemetry across all registered targets
    sorted_by_csl = sorted(all_plans, key=lambda x: x["csl_index_7d"])
    if sorted_by_csl:
        mid_idx = len(sorted_by_csl) // 2
        median_csl = sorted_by_csl[mid_idx]["csl_index_7d"]
        best_plan = sorted_by_csl[0]
        worst_plan = sorted_by_csl[-1]
    else:
        median_csl = 0.0
        best_plan = {"provider_name": "-", "plan_name": "-", "csl_index_7d": 0.0}
        worst_plan = {"provider_name": "-", "plan_name": "-", "csl_index_7d": 0.0}

    # Artificial Analysis style 3-Column Triptych Benchmark Bars
    def _short_label(p_item: dict) -> str:
        prov = p_item["provider_name"].split(" (")[0].split("（")[0]
        return f"{prov} · {p_item['claimed_model']}"

    triptych_csl_picks = (
        sorted_by_csl[:4] + sorted_by_csl[-3:]
        if len(sorted_by_csl) >= 7
        else sorted_by_csl
    )
    csl_bars_html = []
    for sp in triptych_csl_picks:
        v = sp["csl_index_7d"]
        w = min(100, max(12, int((v / 20.0) * 100)))
        col = "var(--status-err-fg)" if v >= 15.0 else "var(--accent)"
        csl_bars_html.append(
            f'<div class="aa-bar-row" title="{html.escape(sp["provider_name"])} — {html.escape(sp["plan_name"])}">'
            f'<span class="aa-bar-lbl">{html.escape(_short_label(sp))}</span>'
            f'<div class="aa-bar-track"><div class="aa-bar-fill" style="width:{w}%;background:{col};"></div></div>'
            f'<span class="aa-bar-val" style="color:{col if v >= 15.0 else "var(--text-primary)"};">{v:.1f}</span>'
            "</div>"
        )

    sorted_by_drift = sorted(all_plans, key=lambda x: x["peak_delta_csl"])
    triptych_drift_picks = (
        sorted_by_drift[:4] + sorted_by_drift[-3:]
        if len(sorted_by_drift) >= 7
        else sorted_by_drift
    )
    drift_bars_html = []
    for sp in triptych_drift_picks:
        dv = sp["peak_delta_csl"]
        w = min(100, max(10, int((dv / 8.0) * 100)))
        col = "var(--status-err-fg)" if dv >= 5.0 else "var(--status-sim-fg)"
        drift_bars_html.append(
            f'<div class="aa-bar-row" title="{html.escape(sp["provider_name"])} — {html.escape(sp["plan_name"])}">'
            f'<span class="aa-bar-lbl">{html.escape(_short_label(sp))}</span>'
            f'<div class="aa-bar-track"><div class="aa-bar-fill" style="width:{w}%;background:{col};"></div></div>'
            f'<span class="aa-bar-val">+{dv:.1f}</span>'
            "</div>"
        )

    sorted_by_tps = sorted(all_plans, key=lambda x: x["median_tps"], reverse=True)
    triptych_tps_picks = sorted_by_tps[:7]
    tps_bars_html = []
    for sp in triptych_tps_picks:
        tv = sp["median_tps"]
        w = min(100, max(15, int((tv / 100.0) * 100)))
        tps_bars_html.append(
            f'<div class="aa-bar-row" title="{html.escape(sp["provider_name"])} — {html.escape(sp["plan_name"])} (TTFT {sp["ttft_ms"]}ms)">'
            f'<span class="aa-bar-lbl">{html.escape(_short_label(sp))}</span>'
            f'<div class="aa-bar-track"><div class="aa-bar-fill" style="width:{w}%;background:var(--status-ver-fg);"></div></div>'
            f'<span class="aa-bar-val">{tv:.0f}T</span>'
            "</div>"
        )

    # Artificial Analysis style 2D Pareto Frontier Quadrant SVG (X: TPS 38..102, Y: CSL 6.5..20.0 inverted)
    # Plot box: x in [64, 1076], y in [22, 232]
    def _px(tps_v: float) -> float:
        return round(64.0 + ((max(38.0, min(102.0, tps_v)) - 38.0) / 64.0) * 1012.0, 1)

    def _py(csl_v: float) -> float:
        return round(22.0 + ((max(6.5, min(20.0, csl_v)) - 6.5) / 13.5) * 210.0, 1)

    # Compute Pareto-optimal frontier (maximize TPS, minimize CSL)
    pareto_pts = []
    best_csl_so_far = 999.0
    for sp in sorted(all_plans, key=lambda x: (-x["median_tps"], x["csl_index_7d"])):
        if sp["csl_index_7d"] < best_csl_so_far:
            pareto_pts.append((_px(sp["median_tps"]), _py(sp["csl_index_7d"])))
            best_csl_so_far = sp["csl_index_7d"]
    pareto_poly = " ".join(f"{x},{y}" for x, y in pareto_pts)

    scatter_nodes = []
    # Explicit per-slug label offsets (dx, dy, text-anchor) to guarantee 0 collisions across all 15 plans
    _label_pos = {
        "minimax": (-8, -7, "end"),
        "xai": (0, 15, "middle"),
        "volcengine": (0, 15, "middle"),
        "openai": (0, 15, "middle"),
        "cursor": (0, -9, "middle"),
        "github-copilot": (9, 4, "start"),
        "commandcode": (9, 3, "start"),
        "aliyun": (-9, 2, "end"),
        "opencode": (-9, 11, "end"),
        "kilocode": (-9, -5, "end"),
        "kiro": (0, 15, "middle"),
        "kimi": (0, -8, "middle"),
        "anthropic": (0, -8, "middle"),
        "xiaomi": (-8, 4, "end"),
        "zai": (9, 4, "start"),
    }
    for sp in sorted_by_tps:
        cx = _px(sp["median_tps"])
        cy = _py(sp["csl_index_7d"])
        c_val = sp["csl_index_7d"]
        dot_col = "var(--status-err-fg)" if c_val >= 15.0 else ("var(--status-ver-fg)" if (c_val <= 13.0 and sp["median_tps"] >= 65) else "var(--accent)")
        short_prov = sp["provider_name"].split(" (")[0].split("（")[0]
        chosen_dx, chosen_dy, anchor = _label_pos.get(sp["provider_slug"], (0, -8, "middle"))
        scatter_nodes.append(
            f'<g><circle cx="{cx}" cy="{cy}" r="4.5" style="fill:{dot_col};stroke:var(--bg-surface);stroke-width:1.5px;"/>'
            f'<text x="{round(cx + chosen_dx, 1)}" y="{round(cy + chosen_dy, 1)}" text-anchor="{anchor}" style="fill:var(--text-body);" font-size="10.5" font-family="var(--font-mono)" font-weight="600">{html.escape(short_prov)} ({c_val:.1f})</text></g>'
        )

    qx = _px(65.0)
    qy_bottom = _py(13.2)
    y_warn15 = _py(15.0)

    # Embroidered Running Hippo Loop (homage to Kbar's Embroidered Loop on recent.design)
    # Anatomical hippo silhouette: chubby barrel rump, shoulder hump, perked small ears,
    # raised eye orbit, huge bulbous hippo snout with nostril dome & open tusked jaw,
    # deep rounded belly, and 4 muscular galloping legs across 4 Muybridge phases.
    _h_torso = (
        "M78,98 C80,76 106,66 138,70 C158,72 174,67 192,74 "
        "C197,76 201,79 204,77 C203,68 211,66 214,75 C217,69 224,69 225,77 "
        "C231,72 239,73 243,80 C257,76 277,80 283,93 C287,102 281,111 271,112 "
        "L252,109 L254,104 L249,108 L266,116 L263,112 L270,118 "
        "C272,126 260,132 245,129 C232,126 222,120 212,123 "
        "C184,142 128,143 96,124 C83,117 77,108 78,98 Z"
    )
    _h_poses = [
        # Frame 1: Full extended gallop stride (legs stretched far out front & back)
        _h_torso
        + " M79,96 C66,99 54,103 46,98 C52,107 65,106 79,103 Z"
        + " M206,120 C222,126 244,134 268,142 C273,144 271,151 263,149 C240,142 216,134 192,126 Z"
        + " M186,125 C184,138 182,149 185,159 L173,159 C170,147 171,135 173,124 Z"
        + " M114,122 C98,134 84,145 72,155 L62,149 C74,137 88,125 100,115 Z"
        + " M96,114 C74,121 54,126 38,128 L35,120 C52,116 72,111 90,103 Z",
        # Frame 2: Cross-over gather stride (front & hind legs sweeping inward)
        _h_torso
        + " M79,97 C66,102 55,108 49,106 C55,113 67,109 79,103 Z"
        + " M204,120 C212,133 216,145 212,157 L200,155 C203,143 198,132 188,124 Z"
        + " M184,124 C172,136 160,147 148,155 L140,148 C152,139 162,129 170,121 Z"
        + " M114,122 C124,134 134,145 144,154 L134,159 C122,148 110,136 100,118 Z"
        + " M98,116 C88,130 80,142 74,152 L64,147 C70,135 78,122 88,108 Z",
        # Frame 3: Airborne gathered suspension (legs tucked tightly under barrel belly)
        _h_torso
        + " M80,95 C67,105 57,114 51,119 C60,119 70,110 79,102 Z"
        + " M204,118 C216,126 218,136 202,147 L194,140 C205,133 203,126 188,122 Z"
        + " M182,122 C170,137 158,149 146,157 L137,150 C149,141 160,130 168,120 Z"
        + " M116,120 C132,131 148,140 160,146 L153,153 C138,146 120,136 102,118 Z"
        + " M100,115 C112,130 124,142 132,151 L122,155 C112,144 98,131 88,110 Z",
        # Frame 4: Uncoiling mid-extension reach
        _h_torso
        + " M79,96 C65,97 53,98 46,92 C52,102 65,102 79,102 Z"
        + " M206,120 C224,128 242,138 256,147 L248,154 C234,144 214,134 190,124 Z"
        + " M186,124 C192,137 198,148 202,158 L190,159 C186,147 180,136 172,123 Z"
        + " M112,122 C102,136 94,148 86,158 L76,154 C84,142 92,129 98,116 Z"
        + " M96,114 C78,124 62,132 48,137 L43,129 C58,123 74,114 88,104 Z",
    ]
    _romans = ["I.", "II.", "III.", "IV."]
    _ground_shifts = [0, -14, -28, -7]
    emb_frames_svg = []
    for f_idx in range(4):
        top_p = _h_poses[f_idx]
        bot_p = _h_poses[(f_idx + 2) % 4]
        gx = _ground_shifts[f_idx]
        emb_frames_svg.append(
            f'<g class="emb-frame emb-f{f_idx + 1}">'
            f'<text x="26" y="42" fill="#2B1E1A" font-family="Georgia,serif" font-size="14" font-weight="700" letter-spacing="0.04em">{_romans[f_idx]}</text>'
            f'<g transform="translate(8,-18)"><path d="{top_p}" fill="#2B1E1A"/>'
            f'<path d="M104,96 L248,96 M96,109 L228,109 M120,118 L196,118" stroke="#F2EFE6" stroke-width="0.9" stroke-opacity="0.52"/>'
            f'<path d="M{124+gx},158 L{158+gx},158 M{174+gx},158 L{192+gx},158 M{208+gx},158 L{222+gx},158" stroke="#2B1E1A" stroke-width="2.6" stroke-linecap="round"/></g>'
            f'<g transform="translate(8,162)"><path d="{bot_p}" fill="#2B1E1A"/>'
            f'<path d="M108,98 L242,98 M98,111 L220,111" stroke="#F2EFE6" stroke-width="0.9" stroke-opacity="0.52"/></g>'
            "</g>"
        )
    embroidered_hippo_html = (
        '<div class="emb-card" role="img" aria-label="CSL-Meter embroidered running hippo badge (CLAIMS ARE NOT REAL · LET CSL MEASURE YOU)">'
        '<svg class="emb-svg" viewBox="0 0 320 356" xmlns="http://www.w3.org/2000/svg">'
        "<defs>"
        '<pattern id="linenWeave" width="4" height="4" patternUnits="userSpaceOnUse">'
        '<rect width="4" height="4" fill="#F2EFE6"/>'
        '<rect x="0" y="0" width="2" height="1" fill="#E4DECFE0"/>'
        '<rect x="2" y="2" width="2" height="1" fill="#E4DECFE0"/>'
        '<rect x="0" y="1" width="1" height="2" fill="#FAF8F1"/>'
        '<rect x="2" y="3" width="1" height="1" fill="#D9D2C280"/>'
        "</pattern>"
        '<filter id="embStitch" x="-6%" y="-6%" width="112%" height="112%">'
        '<feTurbulence type="fractalNoise" baseFrequency="0.18 0.52" numOctaves="3" seed="5" result="n"/>'
        '<feDisplacementMap in="SourceGraphic" in2="n" scale="2.6" xChannelSelector="R" yChannelSelector="G" result="d"/>'
        '<feDropShadow dx="0" dy="0.7" stdDeviation="0.55" flood-color="#5A463C" flood-opacity="0.42"/>'
        "</filter>"
        "</defs>"
        '<rect width="320" height="356" rx="6" fill="url(#linenWeave)"/>'
        '<g filter="url(#embStitch)">'
        + "".join(emb_frames_svg)
        + '<text x="160" y="182" text-anchor="middle" fill="#2B1E1A" font-family="Georgia,\'Times New Roman\',serif" font-weight="900" font-size="20.5" letter-spacing="-0.02em" transform="scale(0.94,1.08) translate(10,-13)">CLAIMS ARE NOT REAL</text>'
        '<text x="160" y="206" text-anchor="middle" fill="#2B1E1A" font-family="Georgia,\'Times New Roman\',serif" font-weight="900" font-size="20.5" letter-spacing="-0.02em" transform="scale(0.94,1.08) translate(10,-14)">LET CSL MEASURE YOU</text>'
        '<text x="160" y="220" text-anchor="middle" fill="#4A3730" font-family="var(--font-mono)" font-weight="700" font-size="8.5" letter-spacing="0.14em">CSL-METER · KONSPACE.CC · JSD FINGERPRINT</text>'
        "</g></svg></div>"
    )

    def sort_link(col_key: str, label: str, is_num: bool = True, title: str = "") -> str:
        next_ord = "asc" if (sort_by == col_key and order == "desc") else "desc"
        arrow = ""
        cls = ""
        if sort_by == col_key:
            arrow = " ↓" if order == "desc" else " ↑"
            cls = "sorted"
        th_cls = ' scope="col" class="num"' if is_num else ' scope="col"'
        title_attr = f' title="{html.escape(title)}"' if title else ""
        return f'<th{th_cls}><a class="{cls}"{title_attr} href="/?category={html.escape(cat)}&amp;origin={html.escape(origin_filter)}&amp;sort={col_key}&amp;order={next_ord}">{label}{arrow}</a></th>'

    rows_html = []
    if not plans:
        rows_html.append(
            '<tr><td colspan="12" style="text-align:center;padding:28px 16px;color:var(--text-muted);">'
            '<div style="font-weight:600;color:var(--text-primary);margin-bottom:4px;">No Server-Verified records under the current filters</div>'
            '<div>Run the first probe from the Live Probe panel above with a valid API key, or <a href="/?category='
            + html.escape(cat)
            + '&amp;origin=all">switch to the &quot;including simulated baselines&quot; view</a>.</div>'
            "</td></tr>"
        )
    for p in plans:
        p_slug = html.escape(p["provider_slug"])
        pl_slug = html.escape(p["plan_slug"])
        csl = p["csl_index_7d"]
        bar_w = min(100, max(8, int((csl / 28.0) * 100)))
        bar_cls = "csl-bar-fill csl-bar-fill--warn" if csl >= 15.0 else "csl-bar-fill"
        csl_val_color = "var(--status-err-fg)" if csl >= 15.0 else "var(--text-primary)"
        is_sim = p.get("data_origin") != "Server-Verified"
        origin_tag = "Simulated" if is_sim else f"Verified({p.get('verified_sample_count', 1)})"
        origin_chip_cls = "tag-chip tag-simulated" if is_sim else "tag-chip tag-verified"
        delta_v = p["peak_delta_csl"]
        delta_w = min(100, max(10, int((delta_v / 9.0) * 100)))
        delta_cls = "delta-fill delta-fill--high" if delta_v >= 5.0 else "delta-fill"

        rows_html.append(
            f'<tr>'
            f'<td class="provider-cell" title="{html.escape(p["provider_name"])} — {html.escape(p["plan_name"])}">'
            f'<div style="font-weight:600;color:var(--text-primary);white-space:nowrap;">{html.escape(p["provider_name"])}</div>'
            f'<div class="plan-name" style="color:var(--text-muted);font-size:11px;">{html.escape(p["plan_name"])}</div></td>'
            f'<td><span class="{origin_chip_cls}">{origin_tag}</span></td>'
            f'<td class="mono">{html.escape(p["claimed_model"])} <span class="harness-key">[{html.escape(p["harness_type"])}]</span></td>'
            f'<td class="num">{p["sample_count_7d"]}</td>'
            f'<td class="num"><div class="csl-bar-wrap">'
            f'<div class="csl-bar-bg" title="CSL index {csl:.1f} (marker line = 15.0 alert threshold)"><div class="{bar_cls}" style="width:{bar_w}%;"></div></div>'
            f'<span style="color:{csl_val_color};font-weight:700;">{csl:.1f}</span>'
            f'<span style="color:var(--text-muted);font-size:11px;">±{p["csl_iqr"]:.1f}</span></div></td>'
            f'<td class="num" title="±{p["jsd_std"]:.3f}">{p["net_jsd"]:.3f}</td>'
            f'<td class="num">{p["split_jsd"]:.3f} <span style="color:var(--text-muted);">({p["tail_ratio"]:.0f}%)</span></td>'
            f'<td class="mono">{html.escape(p["nearest_profile"])}</td>'
            f'<td class="num"><div class="delta-pill" title="14:00-18:00 peak drift +{delta_v:.1f}">'
            f'<div class="delta-track"><div class="{delta_cls}" style="width:{delta_w}%;"></div></div>'
            f'<span>+{delta_v:.1f}</span></div></td>'
            f'<td class="num">{p["token_ratio"]:.2f}x <span style="color:var(--text-muted);">({p["cache_hit_pct"]:.0f}%)</span></td>'
            f'<td class="num tput-cell"><div>{p["median_tps"]:.0f}T</div><div class="tput-sub">{p["ttft_ms"]}ms · {p["rate_429_pct"]:.1f}%</div></td>'
            f'<td class="num"><a href="/timeline?p1={p_slug}/{pl_slug}" class="mono" style="font-size:11px;">Peaks</a> · '
            f'<a href="/badge/plan/{p_slug}/{pl_slug}.svg" class="mono" style="font-size:11px;" target="_blank" rel="noopener">Badge</a></td>'
            f'</tr>'
        )

    plan_options_html = []
    for p in all_plans:
        val = f"{p['provider_slug']}|{p['plan_slug']}|{p['claimed_model']}|{p['harness_type']}"
        label = f"{p['provider_name']} — {p['plan_name']} [{p['claimed_model']}]"
        plan_options_html.append(f'<option value="{html.escape(val)}">{html.escape(label)}</option>')

    recent_rows_html = []
    for r in recent_reports:
        rid = html.escape(r["uuid"])
        is_ver = r.get("data_origin") == "Server-Verified"
        vmode = "Server-Verified" if is_ver else "Simulated · 模拟生成"
        vchip_cls = "tag-chip tag-verified" if is_ver else "tag-chip tag-simulated"
        recent_rows_html.append(
            f'<tr>'
            f'<td class="mono"><a href="/r/{rid}" style="font-weight:600;">#{rid}</a></td>'
            f'<td class="mono" style="color:var(--text-muted);">{html.escape(r["created_at"])}</td>'
            f'<td class="provider-cell" title="{html.escape(r["provider_name"])} · {html.escape(r["plan_name"])}">{html.escape(r["provider_name"])} · {html.escape(r["plan_name"])}</td>'
            f'<td class="mono">{html.escape(r["claimed_model"])}</td>'
            f'<td><span class="{vchip_cls}">{html.escape(vmode)}</span></td>'
            f'<td class="num" style="color:var(--text-primary);font-weight:700;">{r["csl_index"]:.1f}</td>'
            f'<td class="num">{r["net_jsd"]:.3f}</td>'
            f'<td class="num">{r["split_jsd"]:.3f}</td>'
            f'<td class="mono">{html.escape(r["nearest_profile"])}</td>'
            f'<td class="num">{r["tps"]:.1f} TPS</td>'
            f'<td class="num"><a href="/r/{rid}" class="mono">View snapshot →</a></td>'
            f'</tr>'
        )

    turnstile_head_script = (
        '<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>'
        if site_key
        else ""
    )
    turnstile_widget_html = (
        f'<div class="cf-turnstile" data-sitekey="{html.escape(site_key)}" data-theme="light"></div>'
        if site_key
        else '<div class="turnstile-slot mono">Turnstile slot ready (TURNSTILE_SITE_KEY not injected)</div>'
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CSL-Meter — Independent CSL Observatory for AI Subscription &amp; API Plans (konspace.cc)</title>
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

    <section class="aa-hero" aria-label="Observatory charter">
      <div class="aa-hero__left">
        <div class="aa-hero__kicker">INDEPENDENT TELEMETRY ANALYSIS OF AI PLANS · KONSPACE.CC</div>
        <h1 class="aa-hero__title">Independent analysis of AI subscription &amp; API plans</h1>
        <div class="aa-hero__zh">An independent public observatory for AI subscription &amp; pay-as-you-go API plans</div>
        <div class="aa-hero__lead">
          Sixteen real upstream API probes per round fingerprint each plan's response distribution, measuring the JS divergence between the claimed model and the served one (the CSL index), 14:00–18:00 peak drift and live throughput. Only reproducible readings are published; credentials are never stored.
        </div>
        <div class="aa-hero__stats">
          <div class="aa-stat-pill">
            <span class="aa-stat-pill__lbl">Site-wide 7d Median CSL</span>
            <span class="aa-stat-pill__num" style="color:var(--accent);">{median_csl:.1f}</span>
          </div>
          <div class="aa-stat-pill">
            <span class="aa-stat-pill__lbl">Best Baseline Fit (Low Drift)</span>
            <span class="aa-stat-pill__num">{best_plan['csl_index_7d']:.1f} <span style="font-size:12px;font-weight:500;color:var(--text-muted);">({html.escape(best_plan['provider_name'])})</span></span>
          </div>
          <div class="aa-stat-pill">
            <span class="aa-stat-pill__lbl">Highest Peak Drift (High Drift)</span>
            <span class="aa-stat-pill__num" style="color:var(--status-err-fg);">{worst_plan['csl_index_7d']:.1f} <span style="font-size:12px;font-weight:500;color:var(--text-muted);">({html.escape(worst_plan['provider_name'])})</span></span>
          </div>
          <div class="aa-stat-pill">
            <span class="aa-stat-pill__lbl">Verified Real-API Samples</span>
            <span class="aa-stat-pill__num">{verified_total} <span style="font-size:12px;font-weight:500;color:var(--text-muted);">/ {len(INITIAL_PLANS)} targets</span></span>
          </div>
        </div>
        <div class="aa-ledger" style="margin-top:8px;" aria-label="Protocol and live log">
          <a href="/timeline" class="aa-ledger__item">
            <div>
              <div class="aa-ledger__kicker">BENCHMARK · 24H PEAK &amp; 30D DRIFT</div>
              <div class="aa-ledger__title">24h peak slices (14:00–18:00 UTC+8) reconciled against 30d version-drift series</div>
            </div>
            <span class="aa-ledger__arrow">↗</span>
          </a>
          <a href="#probe-panel" class="aa-ledger__item">
            <div>
              <div class="aa-ledger__kicker">METHODOLOGY · 16-PROBE JSD FINGERPRINT · {'VERIFIED-LIVE' if verified_total >= len(INITIAL_PLANS) else 'DEMO-SIMULATED'}</div>
              <div class="aa-ledger__title">16 real requests per round (hard cap 30K tokens) · simulated baselines strictly separated from real probes · credentials burned in memory (0 stored)</div>
            </div>
            <span class="aa-ledger__arrow">↓</span>
          </a>
        </div>
      </div>

      {embroidered_hippo_html}
    </section>

    <div class="aa-toolbar" role="region" aria-label="Dimension and category switcher">
      <div class="aa-pill-group" role="group" aria-label="Plan categories">
        <a href="/?category=all&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="aa-pill {'active' if cat == 'all' else ''}">All Targets ({len(INITIAL_PLANS)})</a>
        <a href="/?category=cn_plan&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="aa-pill {'active' if cat == 'cn_plan' else ''}">China Personal Plans</a>
        <a href="/?category=global_coding&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="aa-pill {'active' if cat == 'global_coding' else ''}">Global Coding Subscriptions</a>
        <a href="/?category=global_oa&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="aa-pill {'active' if cat == 'global_oa' else ''}">Global OA + Grok</a>
        <a href="/?category=payg&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="aa-pill {'active' if cat == 'payg' else ''}">Official Pay-As-You-Go</a>
      </div>
      <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
        <span class="mono" style="font-size:11px;color:var(--text-muted);">Data Scope:</span>
        <div class="aa-pill-group" role="group" aria-label="Data origin">
          <a href="/?category={html.escape(cat)}&amp;origin=all&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="aa-pill {'active' if not only_verified else ''}">Incl. Simulated (All)</a>
          <a href="/?category={html.escape(cat)}&amp;origin=verified&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="aa-pill {'active' if only_verified else ''}">Verified Probes Only ({verified_total})</a>
        </div>
      </div>
    </div>

    <section class="aa-triptych" aria-label="Three core observation panels">
      <div class="aa-card">
        <div class="aa-card__head">
          <div class="aa-card__title"><span class="aa-sq aa-sq--cobalt"></span><span>CSL Fidelity Index</span></div>
          <div class="aa-card__sub">7d composite CSL index · lower means closer to the official full-strength baseline (Lower is better, &lt;15.0)</div>
          <div class="aa-card__prov">⛁ “Simulated” marks simulated baselines · red ≥15.0 flags distribution deviation</div>
        </div>
        <div class="aa-bars">
          {''.join(csl_bars_html)}
        </div>
        <div class="aa-card__foot">
          <span>Range: {best_plan['csl_index_7d']:.1f} – {worst_plan['csl_index_7d']:.1f}</span>
          <span>↗ CSL-Meter</span>
        </div>
      </div>

      <div class="aa-card">
        <div class="aa-card__head">
          <div class="aa-card__title"><span class="aa-sq aa-sq--amber"></span><span>Peak Drift</span></div>
          <div class="aa-card__sub">14:00–18:00 peak vs off-peak ΔCSL · lower is steadier (Lower is better)</div>
          <div class="aa-card__prov">⛁ Covers the afternoon congestion window · ≥+5.0 flags significant peak shift</div>
        </div>
        <div class="aa-bars">
          {''.join(drift_bars_html)}
        </div>
        <div class="aa-card__foot">
          <span>24h Peak Window (UTC+8)</span>
          <span>↗ CSL-Meter</span>
        </div>
      </div>

      <div class="aa-card">
        <div class="aa-card__head">
          <div class="aa-card__title"><span class="aa-sq aa-sq--emerald"></span><span>Throughput</span></div>
          <div class="aa-card__sub">Median output speed (tokens/s) and time-to-first-token · higher is faster (Higher is better)</div>
          <div class="aa-card__prov">⛁ Also records TTFT (ms) and the 429 rate-limit rate</div>
        </div>
        <div class="aa-bars">
          {''.join(tps_bars_html)}
        </div>
        <div class="aa-card__foot">
          <span>Unit: Tokens / sec (TPS)</span>
          <span>↗ CSL-Meter</span>
        </div>
      </div>
    </section>

    <section class="panel" aria-label="CSL fidelity vs throughput Pareto quadrant">
      <div class="panel-head">
        <div class="panel-title">
          <span class="panel-eyebrow">PARETO FRONTIER</span>
          <span>CSL Fidelity Index vs. Median Throughput (TPS) · Pareto quadrant analysis</span>
        </div>
        <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap;">
          <span class="mono" style="font-size:11px;color:var(--text-muted);background:var(--bg-surface);border:1px solid var(--border-hairline);padding:3px 10px;border-radius:999px;">{len(all_plans)} of {len(all_plans)} plans</span>
          <a href="/timeline" class="btn-action">Open 24h peaks &amp; 30d trends →</a>
        </div>
      </div>
      <div class="aa-pareto-legend">
        <span class="aa-legend-item"><span style="width:12px;height:12px;background:var(--status-ver-bg);border:1px solid var(--status-ver-bd);border-radius:2px;display:inline-block;"></span><strong>Most attractive quadrant</strong>(high fidelity CSL ≤ 13.0 · high throughput TPS ≥ 65)</span>
        <span class="aa-legend-item"><span class="mono" style="color:var(--status-ver-fg);font-weight:700;">····</span><strong>Pareto line</strong> (Pareto-optimal frontier)</span>
        <span class="aa-legend-item"><span style="width:8px;height:8px;border-radius:99px;background:var(--accent);display:inline-block;"></span>Normal zone (CSL &lt; 15.0)</span>
        <span class="aa-legend-item"><span style="width:8px;height:8px;border-radius:99px;background:var(--status-err-fg);display:inline-block;"></span>High-deviation alert zone (CSL ≥ 15.0)</span>
        <span class="mono" style="margin-left:auto;font-size:11px;color:var(--text-muted);">⛁ Higher = closer to the official baseline · further right = faster throughput</span>
      </div>
      <div style="padding:12px 16px 10px;background:var(--bg-surface);">
        <svg viewBox="0 0 1120 264" style="width:100%;height:auto;display:block;" role="img" aria-label="CSL index vs measured throughput Pareto scatter">
          <rect x="64" y="22" width="1012" height="210" style="fill:var(--bg-subtle);" rx="4"/>
          <rect x="{qx}" y="22" width="{round(1076.0 - qx, 1)}" height="{round(qy_bottom - 22.0, 1)}" style="fill:var(--status-ver-bg);stroke:var(--status-ver-bd);" stroke-dasharray="4 3" rx="3"/>
          <text x="{round(qx + 10, 1)}" y="38" style="fill:var(--status-ver-fg);" font-size="10.5" font-family="var(--font-mono)" font-weight="700">MOST ATTRACTIVE QUADRANT · low drift, high throughput (CSL ≤ 13.0, TPS ≥ 65)</text>
          <line x1="64" y1="{_py(9.0)}" x2="1076" y2="{_py(9.0)}" style="stroke:var(--border-hairline);" stroke-dasharray="3 3"/>
          <line x1="64" y1="{_py(12.0)}" x2="1076" y2="{_py(12.0)}" style="stroke:var(--border-hairline);" stroke-dasharray="3 3"/>
          <line x1="64" y1="{y_warn15}" x2="1076" y2="{y_warn15}" style="stroke:var(--status-err-bd);" stroke-dasharray="5 4" stroke-width="1.2"/>
          <text x="72" y="{round(y_warn15 - 5, 1)}" style="fill:var(--status-err-fg);" font-size="10" font-family="var(--font-mono)">CSL = 15.0 significant-deviation line (high-drift zone below)</text>
          <line x1="64" y1="{_py(18.0)}" x2="1076" y2="{_py(18.0)}" style="stroke:var(--border-hairline);" stroke-dasharray="3 3"/>
          <text x="56" y="{round(_py(9.0) + 4, 1)}" text-anchor="end" style="fill:var(--text-muted);" font-size="10.5" font-family="var(--font-mono)">9.0</text>
          <text x="56" y="{round(_py(12.0) + 4, 1)}" text-anchor="end" style="fill:var(--text-muted);" font-size="10.5" font-family="var(--font-mono)">12.0</text>
          <text x="56" y="{round(y_warn15 + 4, 1)}" text-anchor="end" style="fill:var(--status-err-fg);" font-size="10.5" font-family="var(--font-mono)" font-weight="700">15.0</text>
          <text x="56" y="{round(_py(18.0) + 4, 1)}" text-anchor="end" style="fill:var(--text-muted);" font-size="10.5" font-family="var(--font-mono)">18.0</text>
          <text x="{_px(45)}" y="250" text-anchor="middle" style="fill:var(--text-muted);" font-size="10.5" font-family="var(--font-mono)">45 TPS</text>
          <text x="{_px(60)}" y="250" text-anchor="middle" style="fill:var(--text-muted);" font-size="10.5" font-family="var(--font-mono)">60 TPS</text>
          <text x="{_px(75)}" y="250" text-anchor="middle" style="fill:var(--text-muted);" font-size="10.5" font-family="var(--font-mono)">75 TPS</text>
          <text x="{_px(90)}" y="250" text-anchor="middle" style="fill:var(--text-muted);" font-size="10.5" font-family="var(--font-mono)">90 TPS</text>
          <polyline fill="none" style="stroke:var(--status-ver-fg);" stroke-width="1.8" stroke-dasharray="5 4" points="{pareto_poly}"/>
          {''.join(scatter_nodes)}
          <text x="1068" y="224" text-anchor="end" style="fill:var(--text-muted);" font-size="10.5" font-family="var(--font-mono)" font-weight="600">↗ Artificial Analysis Style Telemetry · CSL-Meter (konspace.cc)</text>
        </svg>
      </div>
    </section>

    <section class="obs-deck" aria-label="Live upstream API probe">
      <div class="probe-bench" id="probe-panel">
        <div class="probe-bench__head">
          <div class="panel-title">
            <span class="panel-eyebrow">LIVE PROBE</span>
            <span>Run a Real Upstream API Probe (real outbound requests · zero credential retention · no synthetic results)</span>
          </div>
          <div class="mono" style="font-size:11px;color:var(--text-muted);">
            Gentle 4-way concurrency · 16 real requests (~1,100 tokens, hard cap 30,000 tokens) · fewer than 8 valid extractions = no report
          </div>
        </div>
        <form id="probe-form" onsubmit="return submitProbe(event);">
          <div class="probe-grid">
            <div class="field-group">
              <label class="field-label" for="plan-selector"><span class="step-num">01</span>Select a whitelisted personal plan / official pay-as-you-go baseline (custom URLs blocked, anti-SSRF)</label>
              <select id="plan-selector" class="field-select" required>
                {''.join(plan_options_html)}
              </select>
            </div>
            <div class="field-group">
              <label class="field-label" for="quota-stage"><span class="step-num">02</span>Current 5h quota-window stage</label>
              <select id="quota-stage" class="field-select">
                <option value="window_early (&lt;30%)">Early window (&lt;30% used)</option>
                <option value="window_late (&gt;70%)">Late window (&gt;70% used)</option>
                <option value="fallback_triggered">After throttling / quota fallback</option>
              </select>
            </div>
            <div class="field-group">
              <label class="field-label" for="api-key-input"><span class="step-num">03</span>Temporary test credential (burned in memory after use)</label>
              <input id="api-key-input" type="password" class="field-input" placeholder="sk-... (never stored)" required minlength="6" autocomplete="off"/>
            </div>
            <div class="field-group">
              <span class="field-label"><span class="step-num">04</span>Human verification (Cloudflare Turnstile)</span>
              {turnstile_widget_html}
            </div>
            <div class="field-group">
              <button type="submit" id="submit-btn" class="btn-submit">Run real probe →</button>
            </div>
          </div>
        </form>
        <div class="notice-bar">
          <span>Verification boundary: the server uses this credential to make 16 real requests to the official whitelisted API (about 4–10 seconds); the credential lives only in memory and is burned after use; an invalid key or an upstream 401/403 fails loudly and produces no report.</span>
          <span id="probe-status" class="mono" style="color:var(--accent);font-weight:600;" role="status" aria-live="polite">Waiting for a real test credential...</span>
        </div>
      </div>
    </section>

    <section class="panel" aria-label="Global plan and provider statistics">
      <div class="panel-head">
        <div class="panel-title">
          <span class="panel-eyebrow">MATRIX</span>
          <span>All Plans &amp; Providers — Objective Statistics (flat, factual, by the numbers)</span>
        </div>
        <div class="filter-bar">
          <div class="seg-group" role="group" aria-label="Data origin filter">
            <a href="/?category={html.escape(cat)}&amp;origin=all&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if not only_verified else ''}">Incl. Simulated</a>
            <a href="/?category={html.escape(cat)}&amp;origin=verified&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if only_verified else ''}">Verified Probes Only ({verified_total})</a>
          </div>
          <div class="seg-group" role="group" aria-label="Category filter">
            <a href="/?category=all&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'all' else ''}">All</a>
            <a href="/?category=cn_plan&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'cn_plan' else ''}">China Personal Plans</a>
            <a href="/?category=global_coding&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'global_coding' else ''}">Global Coding Subscriptions</a>
            <a href="/?category=global_oa&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'global_oa' else ''}">Global OA + Grok</a>
            <a href="/?category=payg&amp;origin={html.escape(origin_filter)}&amp;sort={html.escape(sort_by)}&amp;order={html.escape(order)}" class="tab-pill {'active' if cat == 'payg' else ''}">Official Pay-As-You-Go</a>
          </div>
        </div>
      </div>
      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              {sort_link('provider_name', 'Provider / Plan', False)}
              <th scope="col">Data Status</th>
              <th scope="col">Claimed Model [Harness]</th>
              {sort_link('sample_count_7d', 'Samples N')}
              {sort_link('csl_index_7d', 'CSL Index')}
              {sort_link('net_jsd', 'Net-JSD')}
              {sort_link('split_jsd', 'Split-JSD')}
              <th scope="col">Nearest Baseline (Top-1)</th>
              {sort_link('peak_delta_csl', 'Peak Δ')}
              {sort_link('token_ratio', 'Billing/Cache')}
              {sort_link('median_tps', 'Throughput', title='Throughput / TTFT / 429 rate')}
              <th scope="col" class="num">Cite</th>
            </tr>
          </thead>
          <tbody>
            {''.join(rows_html)}
          </tbody>
        </table>
      </div>
      <div class="notice-bar">
        <span>Method note: readings present only the statistical distance (JSD) between sampled distributions and claimed baselines; no subjective verdicts. Simulated demo baselines are never mixed into real probe aggregates.</span>
        <span class="mono" style="display:inline-flex;align-items:center;gap:6px;flex-wrap:wrap;">Live SVG badge:<img src="/badge/plan/volcengine/coding-plan-lite.svg" alt="CSL-Meter Badge" style="vertical-align:middle;height:20px;"/></span>
      </div>
    </section>

    <section class="panel" aria-label="Stored snapshot stream">
      <div class="panel-head">
        <div class="panel-title">
          <span class="panel-eyebrow">STREAM</span>
          <span>Stored Snapshots (Server-Verified strictly separated from Simulated · 模拟生成)</span>
        </div>
        <a href="/r/a49d2e" class="btn-action">View sample snapshot #a49d2e →</a>
      </div>
      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">Snapshot ID</th>
              <th scope="col">Sampled (UTC)</th>
              <th scope="col">Plan</th>
              <th scope="col">Claimed Model</th>
              <th scope="col">Verification</th>
              <th scope="col" class="num">CSL Index</th>
              <th scope="col" class="num">Net-JSD</th>
              <th scope="col" class="num">Split-JSD</th>
              <th scope="col">Nearest Base Distribution</th>
              <th scope="col" class="num">Throughput</th>
              <th scope="col" class="num">Action</th>
            </tr>
          </thead>
          <tbody>
            {''.join(recent_rows_html)}
          </tbody>
        </table>
      </div>
    </section>

    <footer class="footer">
      <div><strong>CSL-Meter</strong> (Consistency, Substitution &amp; Latency Meter) · Production site <a href="https://konspace.cc">https://konspace.cc</a> · API <a href="https://api.konspace.cc">https://api.konspace.cc</a></div>
      <div class="mono">CC-BY-4.0 · Please keep the CSL-Meter badge or a backlink when citing</div>
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
    statusEl.style.color = 'var(--accent)';
    statusEl.textContent = 'Sending 16 real HTTP probe requests to the official whitelisted endpoint, please wait (about 4–10s)...';

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
        statusEl.style.color = 'var(--status-err-fg)';
        statusEl.textContent = 'Probe failed: ' + (data.error || resp.statusText);
        btn.disabled = false;
        return false;
      }}
      statusEl.style.color = 'var(--status-ver-fg)';
      statusEl.textContent = 'Real probe complete! Snapshot #' + data.report.uuid + ' created, redirecting...';
      window.location.href = '/r/' + data.report.uuid;
    }} catch (err) {{
      statusEl.style.color = 'var(--status-err-fg)';
      statusEl.textContent = 'Request error: ' + err;
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

    avg1 = sum(x["csl_index"] for x in series1) / max(1, len(series1))
    avg2 = sum(x["csl_index"] for x in series2) / max(1, len(series2))
    max1 = max((x["csl_index"] for x in series1), default=0.0)
    if mode == "hourly_24h" and len(series1) >= 19:
        peak_slice = series1[14:19]
        peak_avg1 = sum(x["csl_index"] for x in peak_slice) / max(1, len(peak_slice))
    else:
        peak_avg1 = max1
    net_diff_avg = avg1 - avg2

    w, h = 960, 248
    pad_l, pad_r, pad_t, pad_b = 48, 24, 24, 34
    plot_w = w - pad_l - pad_r
    plot_h = h - pad_t - pad_b
    n_pts = max(1, len(series1))

    def pt_list(series: list) -> list:
        pts = []
        for idx, item in enumerate(series):
            x = pad_l + (idx / max(1, n_pts - 1)) * plot_w
            y = pad_t + plot_h - (min(40.0, max(0.0, item["csl_index"])) / 40.0) * plot_h
            pts.append((x, y, item))
        return pts

    pts1 = pt_list(series1)
    pts2 = pt_list(series2)
    poly1 = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts1)
    poly2 = " ".join(f"{x:.1f},{y:.1f}" for x, y, _ in pts2)
    area1 = (
        f"{pts1[0][0]:.1f},{pad_t + plot_h:.1f} "
        + poly1
        + f" {pts1[-1][0]:.1f},{pad_t + plot_h:.1f}"
        if pts1
        else ""
    )

    dots1_svg = "".join(
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="2.6" fill="var(--bg-surface)" stroke="var(--accent)" stroke-width="1.8">'
        f'<title>{html.escape(it["bucket_label"])}: CSL {it["csl_index"]:.1f} · {it["tps"]:.0f} TPS</title></circle>'
        for x, y, it in pts1
    )

    peak_rect = ""
    if mode == "hourly_24h" and n_pts >= 24:
        x1 = pad_l + (14 / 23.0) * plot_w
        x2 = pad_l + (18 / 23.0) * plot_w
        peak_rect = (
            f'<rect x="{x1:.1f}" y="{pad_t}" width="{x2 - x1:.1f}" height="{plot_h}" '
            'fill="var(--accent-soft)" stroke="var(--accent-border)" stroke-dasharray="3,3"/>'
            f'<text x="{(x1+x2)/2:.1f}" y="{pad_t + 14}" fill="var(--accent)" font-size="10" '
            'font-family="monospace" font-weight="600" text-anchor="middle">14:00–18:00 Peak Window (UTC+8)</text>'
        )

    x_labels_svg = []
    step = 2 if mode == "hourly_24h" else 3
    for idx, item in enumerate(series1):
        if idx % step == 0 or idx == n_pts - 1:
            x = pad_l + (idx / max(1, n_pts - 1)) * plot_w
            x_labels_svg.append(
                f'<text x="{x:.1f}" y="{h - 10}" fill="var(--text-muted)" font-size="10" font-family="monospace" text-anchor="middle">{html.escape(item["bucket_label"])}</text>'
            )

    heat_cells = []
    for idx, item in enumerate(series1):
        csl_v = item["csl_index"]
        alpha = min(0.32, max(0.04, (csl_v - 6.0) / 55.0))
        is_peak_hr = mode == "hourly_24h" and (14 <= idx <= 18)
        cell_cls = "heat-cell heat-cell--peak" if is_peak_hr else "heat-cell"
        val_color = "var(--status-err-fg)" if csl_v >= 15.0 else "var(--text-primary)"
        heat_cells.append(
            f"""
            <div class="{cell_cls}" style="background:rgba(15, 82, 186, {alpha:.2f});">
              <div class="mono" style="font-size:10px;color:var(--text-muted);">{html.escape(item['bucket_label'])}</div>
              <div class="mono" style="font-size:12.5px;font-weight:700;color:{val_color};margin-top:2px;">{csl_v:.1f}</div>
              <div class="mono" style="font-size:10px;color:var(--text-muted);">{item['tps']:.0f}T</div>
            </div>
            """
        )

    table_rows = []
    for idx in range(min(len(series1), len(series2))):
        s1 = series1[idx]
        s2 = series2[idx]
        diff = s1["csl_index"] - s2["csl_index"]
        diff_w = min(100, max(8, int((abs(diff) / 12.0) * 100)))
        diff_cls = "delta-fill delta-fill--high" if diff >= 6.0 else "delta-fill"
        c1_color = "var(--status-err-fg)" if s1["csl_index"] >= 15.0 else "var(--accent)"
        table_rows.append(
            f"""
            <tr>
              <td class="mono" style="font-weight:600;">{html.escape(s1['bucket_label'])}</td>
              <td class="num" style="color:{c1_color};font-weight:700;">{s1['csl_index']:.1f}</td>
              <td class="num">{s1['net_jsd']:.3f}</td>
              <td class="num">{s1['tps']:.1f} TPS <span style="color:var(--text-muted);">({s1['rate_429_pct']:.1f}%)</span></td>
              <td class="num" style="color:var(--text-primary);font-weight:600;">{s2['csl_index']:.1f}</td>
              <td class="num">{s2['net_jsd']:.3f}</td>
              <td class="num">{s2['tps']:.1f} TPS <span style="color:var(--text-muted);">({s2['rate_429_pct']:.1f}%)</span></td>
              <td class="num">
                <div class="delta-pill">
                  <div class="delta-track"><div class="{diff_cls}" style="width:{diff_w}%;"></div></div>
                  <span style="font-weight:600;">{diff:+.1f}</span>
                </div>
              </td>
            </tr>
            """
        )

    p1_full = f"{meta1['provider_slug']}/{meta1['plan_slug']}"
    p2_full = f"{meta2['provider_slug']}/{meta2['plan_slug']}"
    heat_grid_cls = "heat-grid-24" if mode == "hourly_24h" else "heat-grid-30"
    is_sim_tl = meta1.get("data_origin") != "Server-Verified"
    tl_origin_label = "Simulated · 模拟生成" if is_sim_tl else "Server-Verified"
    tl_origin_cls = "tag-chip tag-simulated" if is_sim_tl else "tag-chip tag-verified"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>24h Peak Heatband &amp; 30d Drift Curves | CSL-Meter (konspace.cc)</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  <div class="shell">
    {render_header("timeline")}

    <section class="panel" aria-label="Cross-period CSL monitor">
      <div class="panel-head">
        <div class="panel-title">
          <span class="panel-eyebrow">TIMELINE</span>
          <span>Cross-Period CSL Monitor (24h peak heatband &amp; 30d version-drift curves)</span>
        </div>
        <div class="filter-bar">
          <span class="{tl_origin_cls}">{tl_origin_label}</span>
          <div class="seg-group" role="group" aria-label="Time span">
            <a href="/timeline?p1={html.escape(p1_full)}&amp;p2={html.escape(p2_full)}&amp;mode=hourly_24h" class="tab-pill {'active' if mode == 'hourly_24h' else ''}">24h Peak Slices (UTC+8)</a>
            <a href="/timeline?p1={html.escape(p1_full)}&amp;p2={html.escape(p2_full)}&amp;mode=daily_30d" class="tab-pill {'active' if mode == 'daily_30d' else ''}">30d Drift Curve</a>
          </div>
        </div>
      </div>

      <form method="GET" action="/timeline" style="padding:var(--sp-3) var(--sp-4);border-bottom:1px solid var(--border-hairline);display:flex;gap:var(--sp-3);align-items:end;flex-wrap:wrap;background:var(--bg-surface);">
        <input type="hidden" name="mode" value="{html.escape(mode)}"/>
        <div class="field-group" style="flex:1;min-width:240px;">
          <label class="field-label" for="tl-p1"><span class="step-num">A</span>Primary plan (cobalt solid line + slice heat matrix below)</label>
          <select id="tl-p1" name="p1" class="field-select">{build_options(meta1['provider_slug'], meta1['plan_slug'])}</select>
        </div>
        <div class="field-group" style="flex:1;min-width:240px;">
          <label class="field-label" for="tl-p2"><span class="step-num">B</span>Reference plan (slate dashed baseline)</label>
          <select id="tl-p2" name="p2" class="field-select">{build_options(meta2['provider_slug'], meta2['plan_slug'])}</select>
        </div>
        <button type="submit" class="btn-submit">Update comparison</button>
      </form>

      <div class="tl-summary-strip">
        <div class="tl-summary-cell">
          <div class="kpi-label">Series A Mean</div>
          <div class="kpi-val" style="color:var(--accent);">{avg1:.1f} <span style="font-size:12px;font-weight:500;color:var(--text-muted);">CSL</span></div>
          <div class="kpi-foot">{html.escape(meta1['provider_name'])} · {html.escape(meta1['plan_name'])}</div>
        </div>
        <div class="tl-summary-cell">
          <div class="kpi-label">{'14:00–18:00 Peak Mean' if mode == 'hourly_24h' else '30d Window Peak'}</div>
          <div class="kpi-val" style="color:{'var(--status-err-fg)' if peak_avg1 >= 15.0 else 'var(--text-primary)'};">{peak_avg1:.1f} <span style="font-size:12px;font-weight:500;color:var(--text-muted);">CSL</span></div>
          <div class="kpi-foot">Drift vs off-peak mean {peak_avg1 - avg1:+.1f}</div>
        </div>
        <div class="tl-summary-cell">
          <div class="kpi-label">Series B Mean</div>
          <div class="kpi-val">{avg2:.1f} <span style="font-size:12px;font-weight:500;color:var(--text-muted);">CSL</span></div>
          <div class="kpi-foot">{html.escape(meta2['provider_name'])} · {html.escape(meta2['plan_name'])}</div>
        </div>
        <div class="tl-summary-cell">
          <div class="kpi-label">Net Gap (Δ A − B)</div>
          <div class="kpi-val">{net_diff_avg:+.1f} <span style="font-size:12px;font-weight:500;color:var(--text-muted);">CSL</span></div>
          <div class="kpi-foot">Claimed model: <span class="mono">{html.escape(meta1['claimed_model'])}</span> vs <span class="mono">{html.escape(meta2['claimed_model'])}</span></div>
        </div>
      </div>

      <div style="padding:var(--sp-4);">
        <div style="margin-bottom:var(--sp-2);display:flex;justify-content:space-between;align-items:center;font-size:var(--fs-sm);flex-wrap:wrap;gap:var(--sp-2);">
          <div style="display:flex;align-items:center;gap:var(--sp-4);flex-wrap:wrap;">
            <span style="color:var(--accent);font-weight:700;">━●━ Primary: {html.escape(meta1['provider_name'])} · {html.escape(meta1['plan_name'])}</span>
            <span style="color:var(--text-muted);font-weight:600;">┅┅ Reference: {html.escape(meta2['provider_name'])} · {html.escape(meta2['plan_name'])}</span>
          </div>
          <div class="mono" style="color:var(--text-muted);font-size:var(--fs-xs);">Y-axis: CSL index (0–40) · 15.0 alert line · lower = closer to the official full-strength distribution</div>
        </div>

        <svg viewBox="0 0 {w} {h}" role="img" aria-label="Two-plan CSL comparison chart" style="width:100%;height:auto;background:var(--bg-canvas);border:1px solid var(--border-hairline);border-radius:var(--radius-sm);display:block;">
          <line x1="{pad_l}" y1="{pad_t}" x2="{w - pad_r}" y2="{pad_t}" stroke="var(--chart-grid)" stroke-width="1"/>
          <line x1="{pad_l}" y1="{pad_t + plot_h*0.5:.1f}" x2="{w - pad_r}" y2="{pad_t + plot_h*0.5:.1f}" stroke="var(--chart-grid)" stroke-width="1" stroke-dasharray="2,3"/>
          <line x1="{pad_l}" y1="{pad_t + plot_h - (15.0/40.0)*plot_h:.1f}" x2="{w - pad_r}" y2="{pad_t + plot_h - (15.0/40.0)*plot_h:.1f}" stroke="var(--status-err-fg)" stroke-width="1" stroke-dasharray="4,4" stroke-opacity="0.55"/>
          <line x1="{pad_l}" y1="{pad_t + plot_h}" x2="{w - pad_r}" y2="{pad_t + plot_h}" stroke="var(--border-strong)" stroke-width="1"/>
          <text x="{pad_l - 8}" y="{pad_t + 4}" fill="var(--text-muted)" font-size="10" font-family="monospace" text-anchor="end">40.0</text>
          <text x="{pad_l - 8}" y="{pad_t + plot_h*0.5 + 4:.1f}" fill="var(--text-muted)" font-size="10" font-family="monospace" text-anchor="end">20.0</text>
          <text x="{pad_l - 8}" y="{pad_t + plot_h - (15.0/40.0)*plot_h + 3:.1f}" fill="var(--status-err-fg)" font-size="10" font-family="monospace" font-weight="600" text-anchor="end">15.0</text>
          <text x="{pad_l - 8}" y="{pad_t + plot_h + 4}" fill="var(--text-muted)" font-size="10" font-family="monospace" text-anchor="end">0.0</text>
          {peak_rect}
          <polygon points="{area1}" fill="var(--accent-soft)" opacity="0.65"/>
          <polyline fill="none" stroke="var(--chart-ref)" stroke-width="1.8" stroke-dasharray="5,4" points="{poly2}"/>
          <polyline fill="none" stroke="var(--accent)" stroke-width="2.4" stroke-linejoin="round" stroke-linecap="round" points="{poly1}"/>
          {dots1_svg}
          {''.join(x_labels_svg)}
        </svg>

        <div style="margin-top:var(--sp-4);">
          <div style="display:flex;justify-content:space-between;align-items:center;font-size:var(--fs-xs);color:var(--text-muted);margin-bottom:var(--sp-2);flex-wrap:wrap;gap:var(--sp-2);">
            <span>Primary plan (<strong>{html.escape(meta1['plan_name'])}</strong>) slice heat matrix (top row: period/date · middle: CSL index · bottom: median TPS):</span>
            <span class="mono">{'24h = 12 cols × 2 rows (14:00–18:00 highlighted)' if mode == 'hourly_24h' else '30d = 10 cols × 3 rows'}</span>
          </div>
          <div class="{heat_grid_cls}">
            {''.join(heat_cells)}
          </div>
        </div>
      </div>
    </section>

    <section class="panel" aria-label="Two-plan slice reconciliation table">
      <div class="panel-head">
        <div class="panel-title">
          <span class="panel-eyebrow">LEDGER</span>
          <span>Slice-by-Slice Reconciliation</span>
        </div>
        <span class="mono" style="font-size:11px;color:var(--text-muted);">API endpoint: {API_DOMAIN}/v1/timeline?provider={html.escape(meta1['provider_slug'])}&amp;plan={html.escape(meta1['plan_slug'])}</span>
      </div>
      <div class="data-table-wrap">
        <table class="data-table">
          <thead>
            <tr>
              <th scope="col">Time Slice</th>
              <th scope="col" class="num">{html.escape(meta1['plan_name'])} · CSL</th>
              <th scope="col" class="num">Primary Net-JSD</th>
              <th scope="col" class="num">Primary TPS (429%)</th>
              <th scope="col" class="num">{html.escape(meta2['plan_name'])} · CSL</th>
              <th scope="col" class="num">Reference Net-JSD</th>
              <th scope="col" class="num">Reference TPS (429%)</th>
              <th scope="col" class="num">CSL Gap (Δ)</th>
            </tr>
          </thead>
          <tbody>
            {''.join(table_rows)}
          </tbody>
        </table>
      </div>
    </section>

    <footer class="footer">
      <div><strong>CSL-Meter</strong> · Production site <a href="https://konspace.cc">https://konspace.cc</a> · API <a href="https://api.konspace.cc">https://api.konspace.cc</a></div>
      <div class="mono">CC-BY-4.0 · Data syncs to dynamic badges every 5 seconds</div>
    </footer>
  </div>
</body>
</html>"""


def render_report_not_found_page(report_uuid: str) -> str:
    uid = html.escape(report_uuid)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Snapshot Not Found (#{uid}) | CSL-Meter (konspace.cc)</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  <div class="shell">
    {render_header("report")}
    <section class="panel" style="max-width:720px;margin:var(--sp-8) auto;">
      <div class="panel-head">
        <div class="panel-title">
          <span class="tag-chip" style="color:var(--status-err-fg);background:var(--status-err-bg);border-color:var(--status-err-bd);">404 · SNAPSHOT_NOT_FOUND</span>
          <span>Probe snapshot #{uid} not found</span>
        </div>
        <span class="mono" style="font-size:11px;color:var(--text-muted);">Snapshot not found</span>
      </div>
      <div style="padding:var(--sp-6);">
        <p style="font-size:var(--fs-body);color:var(--text-primary);font-weight:600;margin-bottom:var(--sp-2);">
          The requested snapshot <span class="mono">#{uid}</span> does not exist in the current observatory database.
        </p>
        <p style="font-size:var(--fs-body);color:var(--text-body);line-height:1.65;margin-bottom:var(--sp-4);">
          Possible reasons: (1) the snapshot link is misspelled; (2) the probe's real upstream usage exceeded the per-round hard cap (<span class="mono">30,000 Tokens</span>) or yielded fewer than <span class="mono">8</span> valid numeric samples, so it was aborted with zero storage, per the observatory's integrity red line.
        </p>
        <div style="display:flex;gap:var(--sp-3);flex-wrap:wrap;">
          <a href="/" class="btn-submit" style="display:inline-flex;align-items:center;text-decoration:none;">← Back to Plans &amp; Providers</a>
          <a href="/r/a49d2e" class="btn-action" style="height:36px;padding:0 var(--sp-4);">View the standard sample snapshot (#a49d2e)</a>
        </div>
      </div>
      <div class="notice-bar">
        <span>Labeling: Simulated · 模拟生成 marks initial demo baselines; Server-Verified marks real upstream probe records.</span>
        <span class="mono">konspace.cc</span>
      </div>
    </section>
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
    vmode_chip_cls = "tag-chip tag-simulated" if is_sim else "tag-chip tag-verified"
    csl_val = rep["csl_index"]
    csl_color = "var(--status-err-fg)" if csl_val >= 15.0 else "var(--accent)"
    csl_bar_w = min(100, max(8, int((csl_val / 28.0) * 100)))
    csl_bar_cls = "csl-bar-fill csl-bar-fill--warn" if csl_val >= 15.0 else "csl-bar-fill"

    dist_rows_html = []
    for k in PROBE_BUCKETS:
        o_pct = obs.get(k, 0.0) * 100.0
        b_pct = base.get(k, 0.0) * 100.0
        diff_pct = o_pct - b_pct
        o_w = min(100.0, o_pct * 1.75)
        b_w = min(100.0, b_pct * 1.75)
        dist_rows_html.append(
            f"""
            <div class="dist-row">
              <div class="mono" style="font-weight:700;color:var(--text-primary);">#{html.escape(k)}</div>
              <div class="dual-bar-track">
                <div class="bar-obs" style="width:{o_w:.1f}%;" title="Sample share {o_pct:.1f}%"></div>
                <div class="bar-ref" style="width:{b_w:.1f}%;" title="Official baseline {b_pct:.1f}%"></div>
              </div>
              <div class="num" style="font-size:11px;">
                <span style="color:var(--accent);font-weight:700;">{o_pct:.1f}%</span>
                <span style="color:var(--text-muted);"> / {b_pct:.1f}%</span>
                <span style="color:var(--text-muted);font-size:10px;margin-left:2px;">({diff_pct:+.1f})</span>
              </div>
            </div>
            """
        )

    ranking_rows = []
    for idx, item in enumerate(rep["nearest_ranking"]):
        sim = item["similarity"]
        rank_badge = f'<span class="step-num">#{idx + 1}</span> ' if idx == 0 else f'<span class="mono" style="color:var(--text-muted);font-size:11px;margin-right:4px;">#{idx + 1}</span>'
        ranking_rows.append(
            f"""
            <tr>
              <td class="mono" style="font-weight:600;color:var(--text-primary);">{rank_badge}{html.escape(item['model'])}</td>
              <td><span class="tag-chip">{html.escape(item['family'])}</span></td>
              <td class="num">{item['jsd']:.4f}</td>
              <td class="num">
                <div class="csl-bar-wrap">
                  <div class="csl-bar-bg"><div class="csl-bar-fill" style="width:{min(100, int(sim))}%;"></div></div>
                  <span style="color:var(--accent);font-weight:700;">{sim:.1f}%</span>
                </div>
              </td>
            </tr>
            """
        )

    ascii_block = (
        f"╭─ ⚡ CSL-Meter (konspace.cc) Data Snapshot (#{rep['uuid']}) ────────────────╮\n"
        f"│ Plan: {rep['provider_name']} · {rep['plan_name'][:22]} │\n"
        f"│ Claimed: {rep['claimed_model']:<18} | Window: {rep['quota_window_stage']:<16} │\n"
        f"│ CSL Index: {rep['csl_index']:<6.1f}             | Net-JSD: {rep['net_jsd']:<6.3f} │\n"
        f"│ Nearest base: {rep['nearest_profile']:<16} | Split-JSD: {rep['split_jsd']:<6.3f}       │\n"
        f"│ Throughput: {rep['tps']:<5.1f} TPS ({rep['rate_429_pct']:.1f}% 429)   | Cache hit: {rep['cache_hit_pct']:.1f}% | Billing ratio: {rep['token_ratio']:.2f}x │\n"
        f"│ Data status: {vmode_display:<18} | Raw distribution: {SITE_DOMAIN}/r/{rep['uuid']} │\n"
        f"╰───────────────────────────────────────────────────────────────╯"
    )

    md_badge_code = f"[![CSL-Meter]({SITE_DOMAIN}/badge/r/{rep['uuid']}.svg)]({SITE_DOMAIN}/r/{rep['uuid']})"
    md_plan_badge = f"[![CSL-Meter]({SITE_DOMAIN}/badge/plan/{p_slug}/{pl_slug}.svg)]({SITE_DOMAIN}/timeline?p1={p_slug}/{pl_slug})"
    iframe_code = f'<iframe src="{SITE_DOMAIN}/embed/r/{rep["uuid"]}" width="100%" height="220" frameborder="0"></iframe>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Snapshot #{uid} ({html.escape(rep['plan_name'])})｜CSL-Meter (konspace.cc)</title>
  <style>{SHARED_CSS}</style>
</head>
<body>
  <div class="shell">
    {render_header("report")}

    <section class="forensic-deck" aria-label="Snapshot forensic readings">
      <div class="forensic-col">
        <div class="obs-eyebrow">
          <span class="obs-eyebrow__tag">PRIMARY CSL INDEX (0–100)</span>
          <span class="mono" style="font-size:11px;color:var(--text-muted);">Snapshot #{uid}</span>
        </div>
        <div style="display:flex;align-items:baseline;gap:var(--sp-3);margin:var(--sp-1) 0;">
          <div class="obs-stat__val" style="color:{csl_color};font-size:clamp(2rem, 2.8vw, 2.5rem);">{csl_val:.1f}</div>
          <div class="csl-bar-bg" style="width:88px;height:8px;"><div class="{csl_bar_cls}" style="width:{csl_bar_w}%;"></div></div>
        </div>
        <div class="telemetry-mini-grid">
          <div>
            <div class="kpi-label">De-shelled Net-JSD</div>
            <div class="mono" style="font-weight:700;color:var(--text-primary);">{rep['net_jsd']:.3f}</div>
          </div>
          <div>
            <div class="kpi-label">Raw-JSD</div>
            <div class="mono" style="font-weight:600;color:var(--text-body);">{rep['raw_jsd']:.3f}</div>
          </div>
          <div>
            <div class="kpi-label">Split-JSD</div>
            <div class="mono" style="font-weight:600;color:var(--text-body);">{rep['split_jsd']:.3f}</div>
          </div>
        </div>
      </div>

      <div class="forensic-col">
        <div class="obs-eyebrow">
          <span class="obs-eyebrow__tag">TARGET &amp; NEAREST BASELINE MATCH</span>
          <span class="harness-key">[{html.escape(rep['harness_type'])}]</span>
        </div>
        <div>
          <div style="font-weight:700;font-size:var(--fs-h2);color:var(--text-primary);">{html.escape(rep['provider_name'])} · {html.escape(rep['plan_name'])}</div>
          <div class="mono" style="font-size:var(--fs-xs);color:var(--text-muted);margin-top:2px;">Claimed model: <strong style="color:var(--text-primary);">{html.escape(rep['claimed_model'])}</strong> · Quota window: {html.escape(rep['quota_window_stage'])}</div>
        </div>
        <div class="telemetry-mini-grid" style="grid-template-columns:1.2fr 1fr;">
          <div>
            <div class="kpi-label">Nearest Golden Baseline (Top-1)</div>
            <div class="mono" style="font-weight:700;color:var(--accent);font-size:13px;">{html.escape(rep['nearest_profile'])}</div>
          </div>
          <div>
            <div class="kpi-label">Runner-up Candidate (Top-2)</div>
            <div class="mono" style="font-weight:600;color:var(--text-body);font-size:12px;">{html.escape(rep['second_profile'])}</div>
          </div>
        </div>
      </div>

      <div class="forensic-col">
        <div class="obs-eyebrow">
          <span class="obs-eyebrow__tag">PROVENANCE &amp; TELEMETRY</span>
          <span class="{vmode_chip_cls}">{html.escape(vmode_display)}</span>
        </div>
        <div class="mono" style="font-size:var(--fs-xs);color:var(--text-muted);">
          Sampled (UTC): <strong style="color:var(--text-body);">{html.escape(rep['created_at'])}</strong>
        </div>
        <div class="telemetry-mini-grid">
          <div>
            <div class="kpi-label">Measured Throughput</div>
            <div class="mono" style="font-weight:700;color:var(--text-primary);">{rep['tps']:.1f} TPS</div>
          </div>
          <div>
            <div class="kpi-label">TTFT</div>
            <div class="mono" style="font-weight:700;color:var(--text-primary);">{rep['ttft_ms']}ms</div>
          </div>
          <div>
            <div class="kpi-label">Billing Ratio / Cache</div>
            <div class="mono" style="font-weight:700;color:var(--text-primary);">{rep['token_ratio']:.2f}x ({rep['cache_hit_pct']:.0f}%)</div>
          </div>
        </div>
      </div>
    </section>

    <div class="grid-2">
      <section class="panel" aria-label="De-shelled distribution comparison">
        <div class="panel-head">
          <div class="panel-title">
            <span class="panel-eyebrow">FINGERPRINT</span>
            <span>De-shelled Sample Distribution vs Official Golden Baseline ({html.escape(rep['claimed_model'])})</span>
          </div>
          <a href="/api/v1/reports/{uid}/raw.json" class="btn-action" download="csl-meter-{uid}.json">Download raw-frequency JSON ↓</a>
        </div>
        <div style="padding:var(--sp-3) var(--sp-4);">
          <div style="display:flex;justify-content:space-between;font-size:var(--fs-xs);color:var(--text-muted);margin-bottom:var(--sp-2);flex-wrap:wrap;gap:var(--sp-1);">
            <span>Probe Feature Buckets (Canonical)</span>
            <span><strong style="color:var(--accent);">■ Sampled distribution</strong> vs <strong style="color:var(--text-muted);">■ Official baseline</strong> (Δ in percentage points)</span>
          </div>
          {''.join(dist_rows_html)}
        </div>
      </section>

      <section class="panel" aria-label="Golden-baseline nearest-neighbor ranking">
        <div class="panel-head">
          <div class="panel-title">
            <span class="panel-eyebrow">NEAREST-5</span>
            <span>Golden Baseline Nearest Neighbors (Harness De-biased Top 5)</span>
          </div>
          <span class="mono" style="font-size:11px;color:var(--text-muted);">Harness: {html.escape(rep['harness_type'])} · {html.escape(rep['quota_window_stage'])}</span>
        </div>
        <div class="data-table-wrap">
          <table class="data-table">
            <thead>
              <tr>
                <th scope="col">Candidate Baseline</th>
                <th scope="col">Model Family</th>
                <th scope="col" class="num">Net-JSD</th>
                <th scope="col" class="num">Distribution Fit</th>
              </tr>
            </thead>
            <tbody>
              {''.join(ranking_rows)}
            </tbody>
          </table>
        </div>
        <div class="notice-bar">
          <span>Objective-reading statement: baselines are ranked purely by JS divergence to the current sample; no subjective verdict is given.</span>
          <span>Data nature: <span class="mono" style="font-weight:600;">{html.escape(vmode_display)}</span></span>
        </div>
      </section>
    </div>

    <section class="panel" aria-label="External citation and sharing components">
      <div class="panel-head">
        <div class="panel-title">
          <span class="panel-eyebrow">CITATION</span>
          <span>Citation &amp; Sharing Components (CSL-Meter / konspace.cc attribution built in)</span>
        </div>
        <img src="/badge/r/{uid}.svg" alt="Snapshot Badge" style="height:22px;max-width:100%;"/>
      </div>
      <div class="citation-grid">
        <div>
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-2);gap:var(--sp-2);">
            <span class="field-label"><span class="step-num">01</span>Community Signature Block [ASCII / Markdown]</span>
            <button type="button" class="btn-action" onclick="copyText('ascii-sig', this)">Copy signature block</button>
          </div>
          <pre id="ascii-sig" class="code-box">{html.escape(ascii_block)}</pre>
        </div>
        <div style="display:flex;flex-direction:column;gap:var(--sp-3);">
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-1);gap:var(--sp-2);">
              <span class="field-label"><span class="step-num">02</span>GitHub / Forum Dynamic SVG Badges (snapshot &amp; live plan aggregate)</span>
              <button type="button" class="btn-action" onclick="copyText('badge-md', this)">Copy Markdown</button>
            </div>
            <pre id="badge-md" class="code-box">{html.escape(md_badge_code)}
{html.escape(md_plan_badge)}</pre>
          </div>
          <div>
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:var(--sp-1);gap:var(--sp-2);">
              <span class="field-label"><span class="step-num">03</span>Iframe Embed Card with Locked Brand Footer</span>
              <button type="button" class="btn-action" onclick="copyText('iframe-snippet', this)">Copy Iframe</button>
            </div>
            <pre id="iframe-snippet" class="code-box">{html.escape(iframe_code)}</pre>
          </div>
        </div>
      </div>
    </section>

    <footer class="footer">
      <div><strong>CSL-Meter</strong> · Production site <a href="https://konspace.cc">https://konspace.cc</a> · API <a href="https://api.konspace.cc">https://api.konspace.cc</a></div>
      <div class="mono">CC-BY-4.0 · Raw JSON and badge APIs are open</div>
    </footer>
  </div>
  <script>
  function copyText(id, btn) {{
    const txt = document.getElementById(id).innerText;
    navigator.clipboard.writeText(txt).then(() => {{
      const old = btn.innerText;
      btn.innerText = 'Copied ✓';
      btn.style.borderColor = 'var(--status-ver-fg)';
      btn.style.color = 'var(--status-ver-fg)';
      setTimeout(() => {{
        btn.innerText = old;
        btn.style.borderColor = '';
        btn.style.color = '';
      }}, 1500);
    }});
  }}
  </script>
</body>
</html>"""


def render_embed_card(title: str, subtitle: str, csl_val: float, jsd_val: float, nearest: str, tps_val: float, n_val: int, target_url: str, is_demo: bool = True) -> str:
    demo_tag = " · DEMO" if is_demo else ""
    status_cls = "tag-chip tag-simulated" if is_demo else "tag-chip tag-verified"
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>CSL-Meter Embed Card</title>
  <style>
    {SHARED_CSS}
    body {{ background: transparent; padding: 0; margin: 0; overflow: hidden; }}
    .calib-strip {{ display: none; }}
    .embed-shell {{
      background: var(--bg-surface);
      border: 1px solid var(--border-strong);
      border-radius: var(--radius-sm);
      height: 210px;
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      overflow: hidden;
    }}
    .embed-body {{ padding: 14px 16px; }}
    .embed-locked-bar {{
      height: 32px;
      background: var(--bg-subtle);
      border-top: 1px solid var(--border-hairline);
      padding: 0 14px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-family: var(--font-mono);
      font-size: 11px;
      color: var(--text-body);
      user-select: none;
    }}
  </style>
</head>
<body>
  <div class="embed-shell">
    <div class="embed-body">
      <div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:12px;gap:8px;">
        <div>
          <div style="color:var(--text-primary);font-weight:700;font-size:14px;">{html.escape(title)}</div>
          <div class="mono" style="color:var(--text-muted);font-size:11px;">{html.escape(subtitle)}</div>
        </div>
        <span class="{status_cls}" style="font-size:12px;padding:3px 8px;">CSL {csl_val:.1f}{demo_tag}</span>
      </div>
      <div style="display:grid;grid-template-columns:repeat(4, 1fr);gap:8px;background:var(--bg-subtle);padding:10px;border-radius:var(--radius-xs);border:1px solid var(--border-hairline);">
        <div>
          <div style="font-size:10px;color:var(--text-muted);">Net-JSD</div>
          <div class="mono" style="font-size:14px;font-weight:700;color:var(--text-primary);">{jsd_val:.3f}</div>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text-muted);">Nearest Base</div>
          <div class="mono" style="font-size:12px;font-weight:600;color:var(--accent);">{html.escape(nearest)}</div>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text-muted);">Median TPS</div>
          <div class="mono" style="font-size:14px;font-weight:700;color:var(--text-primary);">{tps_val:.1f} TPS</div>
        </div>
        <div>
          <div style="font-size:10px;color:var(--text-muted);">Samples</div>
          <div class="mono" style="font-size:14px;font-weight:700;color:var(--text-primary);">N = {n_val}{demo_tag}</div>
        </div>
      </div>
    </div>
    <div class="embed-locked-bar">
      <span><strong>CSL-Meter</strong> Telemetry (konspace.cc){demo_tag}</span>
      <a href="{html.escape(target_url)}" target="_blank" rel="noopener">View raw distribution &amp; reproduction script ↗</a>
    </div>
  </div>
</body>
</html>"""


def render_login_page(error: str = "") -> str:
    err_html = ""
    if error:
        err_html = (
            '<div role="alert" style="background:var(--status-err-bg);border:1px solid var(--status-err-bd);'
            'color:var(--status-err-fg);font-size:var(--fs-sm);font-weight:600;padding:var(--sp-2) var(--sp-3);'
            'border-radius:var(--radius-sm);margin:0 0 var(--sp-4);">'
            + html.escape(error)
            + "</div>"
        )
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>登录 · CSL-Meter (konspace.cc)</title>
<style>
{SHARED_CSS}
.login-stage {{
  min-height: calc(100vh - 140px);
  display: flex;
  align-items: center;
  justify-content: center;
  padding: var(--sp-6) 0;
}}
.login-card {{
  background: var(--bg-surface);
  border: 1px solid var(--border-strong);
  border-radius: var(--radius-md);
  width: min(92vw, 400px);
  box-shadow: var(--shadow-panel);
  overflow: hidden;
}}
.login-card__head {{
  padding: var(--sp-4) var(--sp-5);
  background: var(--bg-subtle);
  border-bottom: 1px solid var(--border-hairline);
}}
.login-card__body {{
  padding: var(--sp-5);
}}
.login-card__foot {{
  padding: var(--sp-3) var(--sp-5);
  background: var(--bg-subtle);
  border-top: 1px solid var(--border-hairline);
  color: var(--text-muted);
  font-size: var(--fs-xs);
  line-height: 1.55;
}}
</style>
</head>
<body>
  <div class="shell">
    {render_header("")}
    <main class="login-stage">
      <form class="login-card" method="post" action="/login">
        <div class="login-card__head">
          <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:4px;">
            <span class="panel-eyebrow">ACCESS GATE</span>
            <span class="mono" style="font-size:11px;color:var(--text-muted);">RESTRICTED</span>
          </div>
          <h1 style="font-size:var(--fs-h1);color:var(--text-primary);font-weight:700;margin:0;">CSL-Meter 登录</h1>
          <p style="color:var(--text-muted);font-size:var(--fs-sm);margin-top:2px;">自托管部署可选启用 · 请验证凭证</p>
        </div>
        <div class="login-card__body">
          {err_html}
          <div class="field-group" style="margin-bottom:var(--sp-3);">
            <label class="field-label" for="u"><span class="step-num">01</span>用户名</label>
            <input id="u" name="username" class="field-input" autocomplete="username" required/>
          </div>
          <div class="field-group" style="margin-bottom:var(--sp-4);">
            <label class="field-label" for="p"><span class="step-num">02</span>口令</label>
            <input id="p" name="password" type="password" class="field-input" autocomplete="current-password" required/>
          </div>
          <button type="submit" class="btn-submit" style="width:100%;">验证并登录 →</button>
        </div>
        <div class="login-card__foot">
          本站观测数据已全部公开，本登录仅供自托管部署在启用 CSL_GATE_PASSWORD_SHA256 时使用，未配置时本站无任何登录拦截。读数标注规则不变：标注 Simulated · 模拟生成 的是模拟基线数据，标注 Server-Verified 的是真实探测记录，请按标注区分。
        </div>
      </form>
    </main>
  </div>
</body>
</html>"""

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
        if path == "/assets/fonts/csl-sans-latin.woff2" and _FONT_LATIN_WOFF2_BYTES:
            self._send_headers(200, "font/woff2", cache_sec=86400)
            self.wfile.write(_FONT_LATIN_WOFF2_BYTES)
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
                f"Claimed model: {plan['claimed_model']} | Peak ΔCSL: +{plan['peak_delta_csl']:.1f}",
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
                f"Snapshot #{rep['uuid']} · {rep['plan_name']}",
                f"Sampled: {rep['created_at']} | Status: {rep['verification_mode']}",
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
                self._send_html(404, render_report_not_found_page(rid))
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
