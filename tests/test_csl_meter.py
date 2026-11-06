#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Unit & Integration Tests for CSL-Meter v1.3 (konspace.cc)
Tests:
1. Demo labeling ('Simulated · 模拟生成', 'DEMO' suffix on SVG badges, 'data_status=demo-simulated' in JSON)
2. Fake Canary Key rejection (no outbound success -> HTTP 502 UPSTREAM_PROBE_FAILED, 0 fake reports written)
3. Real HTTP socket probe execution against a local OpenAI/Anthropic upstream server -> transitions plan to Server-Verified and drops DEMO suffix
4. Cloudflare Turnstile widget rendering + siteverify backend enforcement
5. CSL_GATE_PASSWORD_SHA256 /login gate (302 for HTML, 401 for API with X-Forwarded-For)
6. Zero credential persistence & SSRF blocking
7. Turnstile fail-closed when TURNSTILE_SECRET_KEY is not configured
8. Strict site-wide data_status: verified-live only once EVERY plan is verified
9. Startup migration: a v1-schema database (no data_origin / verified_sample_count
   columns) gains the columns on open, legacy rows are stamped as demo data,
   nothing is lost, and a second open is a no-op (v1.3.1)
10. opencode endpoint points at the Go subscription rail (/zen/go/v1), and its
    probe battery sends the gateway-required x-opencode-session header — one
    fresh id per battery, shared by all 16 requests; other providers send
    none (v1.3.3)
11. Probe report written into a MIGRATED database (data_origin appended last
    by ALTER TABLE, not at position 11 as in a fresh table) lands
    field-perfect — regression guard for the positional-INSERT column shift
    fixed in v1.3.4
12. Reasoning-aware number extraction (plain content / inline <think> /
    reasoning_content fallback / empty) (v1.3.5)
13. Per-battery token budget PROBE_TOKEN_BUDGET=30000 enforced on real
    upstream usage: a stub reporting huge usage aborts the battery with
    PROBE_TOKEN_BUDGET_EXCEEDED and zero reports (v1.3.5)
14. Insufficient probe content: a battery whose distribution samples yield
    no extractable number (reasoning exhausted, content empty) is rejected
    with INSUFFICIENT_PROBE_CONTENT and zero reports (v1.3.5)
15. No owner-only registry route exists in this public tree: both the
    legacy /projects path and any disguised variant answer a plain 404.
"""

import hashlib
import http.client
import json
import os
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import app as csl_app
import csl_engine


class MockUpstreamHandler(BaseHTTPRequestHandler):
    """Real HTTP server simulating upstream OpenAI/Anthropic/Turnstile endpoints over TCP sockets."""

    # v1.3.3: every non-siteverify POST's x-opencode-session header value
    # (None when absent), in arrival order, for the session-header test.
    session_header_log = []
    _record_lock = threading.Lock()

    # v1.3.5: response flavour switch for the budget / insufficient tests.
    # "normal" = pick a number with small usage; "huge" = pick a number but
    # report 5,000 tokens of usage per call; "empty" = reasoning-model
    # exhaustion (no digits in content or reasoning_content).
    response_mode = "normal"

    def log_message(self, fmt, *args):
        return

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length).decode("utf-8", errors="replace")

        if self.path != "/turnstile/siteverify":
            with MockUpstreamHandler._record_lock:
                MockUpstreamHandler.session_header_log.append(
                    self.headers.get("x-opencode-session")
                )

        # Turnstile siteverify mock
        if self.path == "/turnstile/siteverify":
            form = urllib.parse.parse_qs(raw)
            tok = (form.get("response") or [""])[0]
            ok = tok == "VALID_TURNSTILE_TOKEN_2026"
            body = json.dumps({"success": ok, "error-codes": [] if ok else ["invalid-input-response"]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return

        # Check Bearer / x-api-key credential
        auth = self.headers.get("Authorization", "")
        xkey = self.headers.get("x-api-key", "")
        if "INVALID" in auth or "FAKE" in auth or "INVALID" in xkey:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "invalid_api_key"}')
            return

        # Return a realistic OpenAI completion response (flavour per response_mode)
        mode = MockUpstreamHandler.response_mode
        if mode == "huge":
            resp_obj = {
                "id": "chatcmpl-live",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": "42"}}],
                "usage": {
                    "prompt_tokens": 2000,
                    "completion_tokens": 3000,
                    "prompt_tokens_details": {"cached_tokens": 0},
                },
            }
        elif mode == "empty":
            resp_obj = {
                "id": "chatcmpl-live",
                "choices": [{"index": 0, "message": {
                    "role": "assistant",
                    "content": "",
                    "reasoning_content": "Deliberating at length and weighing many possibilities, still undecided.",
                }}],
                "usage": {
                    "prompt_tokens": 112,
                    "completion_tokens": 180,
                    "prompt_tokens_details": {"cached_tokens": 0},
                },
            }
        else:
            picks = ["42", "37", "73", "42", "37", "47", "7", "42"]
            idx = abs(hash(raw + str(threading.get_ident()))) % len(picks)
            resp_obj = {
                "id": "chatcmpl-live",
                "choices": [{"index": 0, "message": {"role": "assistant", "content": picks[idx]}}],
                "usage": {
                    "prompt_tokens": 112,
                    "completion_tokens": 2,
                    "prompt_tokens_details": {"cached_tokens": 96},
                },
            }
        body = json.dumps(resp_obj).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


class TestCSLMeterV13(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.TemporaryDirectory()
        cls.db_path = os.path.join(cls.tmpdir.name, "test_csl_v13.db")
        csl_app.db = csl_engine.CSLDatabase(cls.db_path)

        # Start local HTTP upstream mock server
        cls.upstream_server = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
        cls.upstream_port = cls.upstream_server.server_address[1]
        cls.upstream_thread = threading.Thread(target=cls.upstream_server.serve_forever, daemon=True)
        cls.upstream_thread.start()

        # Start CSL-Meter server
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), csl_app.CSLRequestHandler)
        cls.port = cls.server.server_address[1]
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        csl_engine._TEST_UPSTREAM_BASE_URL = None
        csl_app._TEST_TURNSTILE_VERIFY_URL = None
        os.environ.pop("TURNSTILE_SITE_KEY", None)
        os.environ.pop("TURNSTILE_SECRET_KEY", None)
        os.environ.pop("CSL_GATE_PASSWORD_SHA256", None)
        cls.server.shutdown()
        cls.server.server_close()
        cls.upstream_server.shutdown()
        cls.upstream_server.server_close()
        cls.tmpdir.cleanup()

    def _get(self, path: str, headers: dict = None) -> tuple:
        req = urllib.request.Request(self.base_url + path, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.headers.get("Content-Type", ""), resp.read().decode("utf-8")
        except urllib.error.HTTPError as e:
            return e.code, e.headers.get("Content-Type", ""), e.read().decode("utf-8")

    def _post_json(self, path: str, data: dict, headers: dict = None) -> tuple:
        raw = json.dumps(data).encode("utf-8")
        hdrs = {"Content-Type": "application/json"}
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(self.base_url + path, data=raw, headers=hdrs, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return resp.status, json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode("utf-8"))

    def _raw(self, method: str, path: str, headers: dict = None, body: str = None) -> tuple:
        """Raw HTTP without redirect following (for gate/cookie assertions)."""
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        try:
            conn.request(method, path, body=body, headers=headers or {})
            resp = conn.getresponse()
            data = resp.read().decode("utf-8", errors="replace")
            hdrs = {}
            for k, v in resp.getheaders():
                hdrs.setdefault(k.lower(), v)
            return resp.status, hdrs, data
        finally:
            conn.close()

    def test_01_demo_labeling_and_views(self):
        for path in ("/", "/timeline", "/r/a49d2e"):
            status, ctype, body = self._get(path)
            self.assertEqual(status, 200)
            self.assertIn("Simulated · 模拟生成", body)
            self.assertIn("konspace.cc", body)

        # SVG badge for unprobed plan has DEMO suffix
        status, _, svg = self._get("/badge/plan/volcengine/coding-plan-lite.svg")
        self.assertEqual(status, 200)
        self.assertIn("DEMO", svg)

        # JSON API carries data_status=demo-simulated initially
        status, _, raw_json = self._get("/api/v1/plans")
        self.assertEqual(status, 200)
        data = json.loads(raw_json)
        self.assertEqual(data["data_status"], "demo-simulated")
        self.assertIn("data_notice", data)

    def test_02_fake_canary_key_rejected_no_fake_report(self):
        csl_engine._TEST_UPSTREAM_BASE_URL = f"http://127.0.0.1:{self.upstream_port}"

        # 1. Fail-closed (design rule): with TURNSTILE_SECRET_KEY absent the
        #    submission is rejected before any probing happens. (An earlier
        #    design passed through in this state — fail-open; forbidden now.)
        os.environ.pop("TURNSTILE_SECRET_KEY", None)
        code_closed, res_closed = self._post_json(
            "/api/v1/probe",
            {
                "provider_slug": "openai",
                "plan_slug": "payg-official",
                "api_key": "sk-FAKE-INVALID-CANARY-KEY-0000",
                "cf_turnstile_response": "VALID_TURNSTILE_TOKEN_2026",
            },
        )
        self.assertEqual(code_closed, 403)
        self.assertIn("TURNSTILE_SECRET_NOT_CONFIGURED", res_closed["error"])

        # 2. With Turnstile configured, the fake key passes the human check
        #    and is then rejected by the real upstream probe: HTTP 502 and
        #    zero reports written.
        csl_app._TEST_TURNSTILE_VERIFY_URL = f"http://127.0.0.1:{self.upstream_port}/turnstile/siteverify"
        os.environ["TURNSTILE_SECRET_KEY"] = "0x4AAAAAA_TEST_SECRET_KEY"
        try:
            before_cnt = csl_app.db.count_verified_reports()
            code, res = self._post_json(
                "/api/v1/probe",
                {
                    "provider_slug": "openai",
                    "plan_slug": "payg-official",
                    "api_key": "sk-FAKE-INVALID-CANARY-KEY-0000",
                    "cf_turnstile_response": "VALID_TURNSTILE_TOKEN_2026",
                },
            )
            self.assertEqual(code, 502)
            self.assertIn("UPSTREAM_PROBE_FAILED", res["error"])
            self.assertEqual(csl_app.db.count_verified_reports(), before_cnt)
        finally:
            csl_app._TEST_TURNSTILE_VERIFY_URL = None
            os.environ.pop("TURNSTILE_SECRET_KEY", None)

    def test_03_real_http_probe_and_turnstile_verification(self):
        csl_engine._TEST_UPSTREAM_BASE_URL = f"http://127.0.0.1:{self.upstream_port}"
        csl_app._TEST_TURNSTILE_VERIFY_URL = f"http://127.0.0.1:{self.upstream_port}/turnstile/siteverify"
        os.environ["TURNSTILE_SITE_KEY"] = "0x4AAAAAA_TEST_SITE_KEY"
        os.environ["TURNSTILE_SECRET_KEY"] = "0x4AAAAAA_TEST_SECRET_KEY"

        # 1. Verify cf-turnstile widget is rendered on home page
        _, _, home_html = self._get("/")
        self.assertIn('class="cf-turnstile"', home_html)
        self.assertIn("0x4AAAAAA_TEST_SITE_KEY", home_html)
        self.assertIn("challenges.cloudflare.com/turnstile/v0/api.js", home_html)

        # 2. Missing Turnstile token is rejected with 403
        code_no_ts, res_no_ts = self._post_json(
            "/api/v1/probe",
            {
                "provider_slug": "volcengine",
                "plan_slug": "coding-plan-lite",
                "api_key": "sk-LIVE-VALID-KEY-998877",
            },
        )
        self.assertEqual(code_no_ts, 403)
        self.assertIn("TURNSTILE_TOKEN_MISSING", res_no_ts["error"])

        # 3. Valid Turnstile token + valid upstream key executes 16 real HTTP probes and records Server-Verified
        secret_key = "sk-LIVE-VALID-EPHEMERAL-KEY-5566778899"
        code_ok, res_ok = self._post_json(
            "/api/v1/probe",
            {
                "provider_slug": "volcengine",
                "plan_slug": "coding-plan-lite",
                "quota_window_stage": "window_early (<30%)",
                "api_key": secret_key,
                "cf_turnstile_response": "VALID_TURNSTILE_TOKEN_2026",
            },
        )
        self.assertEqual(code_ok, 200)
        self.assertEqual(res_ok["report"]["verification_mode"], "Server-Verified")
        self.assertEqual(res_ok["report"]["data_origin"], "Server-Verified")

        # Badge for volcengine/coding-plan-lite now drops DEMO suffix and shows N=1 verified sample
        _, _, svg_after = self._get("/badge/plan/volcengine/coding-plan-lite.svg")
        self.assertNotIn("DEMO", svg_after)
        self.assertIn("N=1", svg_after)

        # Ensure secret_key is nowhere in SQLite file
        with open(self.db_path, "rb") as f:
            raw_db = f.read()
        self.assertNotIn(secret_key.encode("utf-8"), raw_db)

        os.environ.pop("TURNSTILE_SITE_KEY", None)
        os.environ.pop("TURNSTILE_SECRET_KEY", None)

    def test_04_login_gate_overlay_preservation(self):
        """Overlay gate semantics, asserted end to end.

        The overlay reads its env at import
        time (production sets it before process start), so the test drives
        the module-level gate settings directly and restores them after.
        """
        pwd = "gate-test-secret"
        xff = {"X-Forwarded-For": "203.0.113.5"}
        saved = (csl_app.GATE_ENABLED, csl_app.GATE_PASSWORD_SHA256, csl_app.GATE_USER)
        csl_app.GATE_USER = "admin"
        csl_app.GATE_PASSWORD_SHA256 = hashlib.sha256(pwd.encode("utf-8")).hexdigest()
        csl_app.GATE_ENABLED = True
        csl_app._sessions.clear()
        try:
            # API + SVG badge via proxy (XFF) without a session -> 401 JSON
            code_api, _, body_api = self._raw("GET", "/api/v1/plans", headers=xff)
            self.assertEqual(code_api, 401)
            self.assertIn("AUTH_REQUIRED", body_api)
            code_badge, _, _ = self._raw("GET", "/badge/plan/volcengine/coding-plan-lite.svg", headers=xff)
            self.assertEqual(code_badge, 401)

            # HTML page via proxy without a session -> 302 to /login
            code_home, hdrs_home, _ = self._raw("GET", "/", headers=xff)
            self.assertEqual(code_home, 302)
            self.assertEqual(hdrs_home.get("location"), "/login")

            # Direct local request (no XFF) is exempt -> 200
            code_local, _, _ = self._raw("GET", "/api/v1/plans")
            self.assertEqual(code_local, 200)

            # Overlay login page: username + password form
            code_login, _, login_html = self._raw("GET", "/login", headers=xff)
            self.assertEqual(code_login, 200)
            self.assertIn("登录 · CSL-Meter", login_html)
            self.assertIn('name="username"', login_html)

            form_ct = {"Content-Type": "application/x-www-form-urlencoded", **xff}
            # Wrong password -> 401, after the overlay's 0.6s failure delay
            t0 = time.time()
            code_bad, _, _ = self._raw(
                "POST", "/login", headers=form_ct,
                body=urllib.parse.urlencode({"username": "admin", "password": "wrong-password"}),
            )
            self.assertEqual(code_bad, 401)
            self.assertGreaterEqual(time.time() - t0, 0.5)

            # Right password but wrong username -> 401 (username is checked)
            code_user, _, _ = self._raw(
                "POST", "/login", headers=form_ct,
                body=urllib.parse.urlencode({"username": "whoever", "password": pwd}),
            )
            self.assertEqual(code_user, 401)

            # Correct credentials -> 302 + overlay session cookie attributes
            code_ok, hdrs_ok, _ = self._raw(
                "POST", "/login", headers=form_ct,
                body=urllib.parse.urlencode({"username": "admin", "password": pwd}),
            )
            self.assertEqual(code_ok, 302)
            self.assertEqual(hdrs_ok.get("location"), "/")
            cookie_hdr = hdrs_ok.get("set-cookie", "")
            self.assertIn("csl_session=", cookie_hdr)
            self.assertIn("Secure", cookie_hdr)
            self.assertIn("Max-Age=43200", cookie_hdr)
            self.assertIn("HttpOnly", cookie_hdr)
            session_cookie = cookie_hdr.split(";")[0]

            # The session opens API access via the proxy
            authd = {"X-Forwarded-For": "203.0.113.5", "Cookie": session_cookie}
            code_auth, _, _ = self._raw("GET", "/api/v1/plans", headers=authd)
            self.assertEqual(code_auth, 200)

            # Already-authenticated GET /login redirects home
            code_again, hdrs_again, _ = self._raw("GET", "/login", headers=authd)
            self.assertEqual(code_again, 302)
            self.assertEqual(hdrs_again.get("location"), "/")

            # /logout revokes the server-side session
            code_out, hdrs_out, _ = self._raw("GET", "/logout", headers=authd)
            self.assertEqual(code_out, 302)
            self.assertEqual(hdrs_out.get("location"), "/login")
            code_revoked, _, _ = self._raw("GET", "/api/v1/plans", headers=authd)
            self.assertEqual(code_revoked, 401)
        finally:
            csl_app.GATE_ENABLED, csl_app.GATE_PASSWORD_SHA256, csl_app.GATE_USER = saved
            csl_app._sessions.clear()

    def test_05_global_data_status_strict_rule(self):
        """Global data_status flips only once EVERY plan has a verified sample.

        Verifies one more plan through the real probe path (deterministic
        against the stub upstream): some-but-not-all plans verified must
        keep the global status at demo-simulated, while per-plan meta tells
        the truth for the verified plan. Flipping every plan row (direct DB
        write, reproducing the end state the probe path produces) must flip
        the global status to verified-live.
        """
        csl_engine._TEST_UPSTREAM_BASE_URL = f"http://127.0.0.1:{self.upstream_port}"
        csl_app._TEST_TURNSTILE_VERIFY_URL = f"http://127.0.0.1:{self.upstream_port}/turnstile/siteverify"
        os.environ["TURNSTILE_SECRET_KEY"] = "0x4AAAAAA_TEST_SECRET_KEY"
        try:
            total = csl_app.db.count_plans()
            self.assertGreater(total, 1)
            before = csl_app.db.count_verified_plans()
            code, res = self._post_json(
                "/api/v1/probe",
                {
                    "provider_slug": "openai",
                    "plan_slug": "payg-official",
                    "api_key": "sk-LIVE-VALID-KEY-112233",
                    "cf_turnstile_response": "VALID_TURNSTILE_TOKEN_2026",
                },
            )
            self.assertEqual(code, 200)
            after = csl_app.db.count_verified_plans()
            self.assertEqual(after, before + 1)
            self.assertLess(after, total)

            # Some but not all plans verified -> global stays demo-simulated
            status, _, raw_json = self._get("/api/v1/plans")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw_json)["data_status"], "demo-simulated")

            # ...while the just-verified plan's own meta is truthful
            status, _, raw_plan = self._get("/api/v1/plans/openai/payg-official")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw_plan)["data_status"], "verified-live")

            # Every plan verified -> global flips
            conn = csl_app.db._connect()
            try:
                conn.execute("UPDATE plans SET data_origin = 'Server-Verified'")
                conn.commit()
            finally:
                conn.close()
            self.assertEqual(csl_app.db.count_verified_plans(), total)
            status, _, raw_json = self._get("/api/v1/plans")
            self.assertEqual(status, 200)
            self.assertEqual(json.loads(raw_json)["data_status"], "verified-live")
        finally:
            csl_app._TEST_TURNSTILE_VERIFY_URL = None
            os.environ.pop("TURNSTILE_SECRET_KEY", None)

    def test_07_opencode_whitelist_endpoint(self):
        """v1.3.3: opencode's whitelist entry must point at the Go subscription rail.

        History: v1.3.2 moved the endpoint off the dead api.opencode.ai host
        (404 / Cloudflare 1010) onto https://opencode.ai/zen/v1 — but that is
        the pay-as-you-go Zen rail, where the real subscription account holds
        no balance: production probes failed 14/14 with HTTP 402
        (production-verified 2026-11-06). The catalog plans are Go
        subscription plans, so the endpoint is the Go rail
        https://opencode.ai/zen/go/v1/chat/completions, and the entry must
        declare the gateway's required session header (see test_08).
        The table entry and the host metadata must agree, validation must
        stay fail-closed, and a provider outside the table must still be
        rejected.
        """
        saved = csl_engine._TEST_UPSTREAM_BASE_URL
        csl_engine._TEST_UPSTREAM_BASE_URL = None
        try:
            ok, endpoint = csl_engine.validate_ssrf_whitelist("opencode")
            self.assertTrue(ok)
            parsed = urllib.parse.urlparse(endpoint)
            self.assertEqual(parsed.hostname, "opencode.ai")
            self.assertTrue(parsed.path.endswith("/zen/go/v1/chat/completions"))
            self.assertEqual(
                csl_engine.ALLOWED_PROVIDERS["opencode"]["host"], "opencode.ai"
            )
            self.assertEqual(
                csl_engine.ALLOWED_PROVIDERS["opencode"].get("session_header"),
                "x-opencode-session",
            )

            ok_bogus, _ = csl_engine.validate_ssrf_whitelist("not-a-real-provider")
            self.assertFalse(ok_bogus)
        finally:
            csl_engine._TEST_UPSTREAM_BASE_URL = saved

    def test_08_opencode_session_header(self):
        """v1.3.3: the opencode Go gateway demands an x-opencode-session header.

        Without it the gateway answers HTTP 400 MissingSessionID; with any
        session id the same real account token gets HTTP 200 on the plan's
        claimed model (production-verified 2026-11-06). So a probe battery
        for a provider that declares "session_header" must send that header
        on every one of its 16 requests, with ONE id shared across the whole
        battery and a FRESH id for the next battery; providers without the
        declaration (e.g. kimi) must send no such header. The id is
        ephemeral: it must not leak into the returned telemetry.
        """
        upstream_base = f"http://127.0.0.1:{self.upstream_port}"
        probe_key = "sk-TEST-SESSION-HEADER-0001"

        def run_battery(provider_slug, model_name):
            with MockUpstreamHandler._record_lock:
                MockUpstreamHandler.session_header_log.clear()
            result = csl_engine.execute_real_upstream_probes(
                provider_slug,
                f"{upstream_base}/{provider_slug}",
                probe_key,
                model_name,
            )
            with MockUpstreamHandler._record_lock:
                seen = list(MockUpstreamHandler.session_header_log)
            return result, seen

        # opencode, battery 1: all 16 requests carry one shared session id
        result1, seen1 = run_battery("opencode", "kimi-k3.1-pro")
        self.assertEqual(len(seen1), 16)
        self.assertTrue(all(isinstance(v, str) and len(v) >= 16 for v in seen1))
        self.assertEqual(len(set(seen1)), 1)
        # The session id is transport-only: it never reaches the telemetry
        self.assertNotIn(seen1[0], json.dumps(result1))

        # opencode, battery 2: a fresh id, again shared across all 16
        _, seen2 = run_battery("opencode", "kimi-k3.1-pro")
        self.assertEqual(len(seen2), 16)
        self.assertEqual(len(set(seen2)), 1)
        self.assertNotEqual(seen2[0], seen1[0])

        # kimi declares no session header: none of its 16 requests carry one
        _, seen_kimi = run_battery("kimi", "kimi-model")
        self.assertEqual(len(seen_kimi), 16)
        self.assertTrue(all(v is None for v in seen_kimi))

    def test_10_reasoning_number_extraction(self):
        """v1.3.5: reasoning-aware number extraction.

        Reasoning models may spend the whole response budget thinking and
        return empty content, or wrap their reasoning in <think> blocks.
        The probe must still recover the chosen number from the reasoning
        channel instead of recording a fallback distribution.
        """
        fn = csl_engine.extract_number_from_reasoning_or_content

        # Case 1: Standard direct content
        self.assertEqual(fn("42"), "42")
        self.assertEqual(fn("The chosen number is 73."), "73")

        # Case 2: Thinking tokens consumed quota, content is empty, reasoning_content has conclusion
        self.assertEqual(fn("", "Let me think carefully. I will pick 42 as the random number."), "42")

        # Case 3: Inline <think> tags in content
        self.assertEqual(fn("<think>Let's consider primes: 37</think>37"), "37")
        self.assertEqual(fn("<think>The user wants an integer between 1 and 100. Choose 47.</think>"), "47")

        # Case 4: Pure empty strings return empty
        self.assertEqual(fn("", ""), "")

    def test_11_probe_token_budget_enforced(self):
        """v1.3.5 ruling A: PROBE_TOKEN_BUDGET=30000 is a hard cap on real usage.

        The stub reports 5,000 tokens per call, so the 14-probe battery
        crosses 30,000 after ~7 results: the battery must abort with
        PROBE_TOKEN_BUDGET_EXCEEDED and file zero reports. (User ruling
        2026-11-06: the cap is a real 30,000; the PRD <3,000 figure is
        superseded and is not what this test asserts.)
        """
        csl_engine._TEST_UPSTREAM_BASE_URL = f"http://127.0.0.1:{self.upstream_port}"
        MockUpstreamHandler.response_mode = "huge"
        try:
            before = csl_app.db.count_verified_reports()
            with self.assertRaises(ValueError) as ctx:
                csl_app.db.record_probe_submission(
                    {
                        "provider_slug": "kimi",
                        "plan_slug": "kimi-code-pro",
                        "api_key": "sk-TEST-BUDGET-0001",
                    }
                )
            self.assertIn("PROBE_TOKEN_BUDGET_EXCEEDED", str(ctx.exception))
            self.assertEqual(csl_app.db.count_verified_reports(), before)
        finally:
            MockUpstreamHandler.response_mode = "normal"

    def test_12_insufficient_probe_content_rejected(self):
        """v1.3.5 ruling B: too few extractable numbers -> no report at all.

        The stub plays a reasoning-exhausted model: HTTP 200 every time,
        but neither content nor reasoning_content contains a digit, so all
        14 distribution samples extract nothing (< 8 required). Submission
        must raise INSUFFICIENT_PROBE_CONTENT and file zero reports —
        probe_quality must have this real consumer, not just exist in the
        telemetry dict (a flag without a consumer would hide this failure).
        """
        csl_engine._TEST_UPSTREAM_BASE_URL = f"http://127.0.0.1:{self.upstream_port}"
        MockUpstreamHandler.response_mode = "empty"
        try:
            before = csl_app.db.count_verified_reports()
            with self.assertRaises(ValueError) as ctx:
                csl_app.db.record_probe_submission(
                    {
                        "provider_slug": "kimi",
                        "plan_slug": "kimi-code-pro",
                        "api_key": "sk-TEST-INSUFFICIENT-0001",
                    }
                )
            self.assertIn("INSUFFICIENT_PROBE_CONTENT", str(ctx.exception))
            self.assertEqual(csl_app.db.count_verified_reports(), before)
        finally:
            MockUpstreamHandler.response_mode = "normal"

    def test_13_no_owner_registry_route_in_public_tree(self):
        """Public export: no project-registry page ships in this tree.

        Both the legacy semantic path and any disguised variant of the
        owner-only registry route are absent: the server answers them
        with the same plain 404 as any other unknown path.
        """
        for path in ("/projects", "/no-such-route-anywhere"):
            code, _, body = self._get(path)
            self.assertEqual(code, 404, path)
            self.assertIn("NOT_FOUND", body)


class TestLegacySchemaMigration(unittest.TestCase):
    """v1.3.1: databases created by v1 code lack the post-v1 columns.

    CREATE TABLE IF NOT EXISTS never alters an existing table, so opening
    such a database must add the missing columns (plans.verified_sample_count,
    plans/reports/timeline_series.data_origin), stamp the pre-existing rows
    with the column defaults, keep every legacy row, and stay a no-op on
    the next open.
    """

    # The three CREATE TABLE statements exactly as v1 shipped them:
    # identical to the current definitions minus the four new columns.
    V1_SCHEMA = """
    CREATE TABLE plans (
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
        updated_at TEXT NOT NULL,
        PRIMARY KEY (provider_slug, plan_slug)
    );
    CREATE TABLE reports (
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
    CREATE TABLE timeline_series (
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
        PRIMARY KEY (provider_slug, plan_slug, bucket_type, bucket_label)
    );
    """

    def _build_v1_db(self, db_path: str):
        conn = sqlite3.connect(db_path)
        try:
            conn.executescript(self.V1_SCHEMA)
            conn.execute(
                """
                INSERT INTO plans (
                    provider_slug, plan_slug, provider_name, plan_name, category,
                    price_label, claimed_model, harness_type, csl_index_7d, csl_iqr,
                    net_jsd, jsd_std, split_jsd, tail_ratio, nearest_profile,
                    second_profile, peak_delta_csl, token_ratio, cache_hit_pct,
                    compression_pct, median_tps, ttft_ms, rate_429_pct,
                    sample_count_7d, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy-provider", "legacy-plan", "Legacy Provider", "Legacy Plan",
                    "subscription", "$9.99/mo", "legacy-model-x", "unknown",
                    88.5, 1.5, 0.012, 0.003, 0.02, 1.25, "profile-a", "profile-b",
                    -0.4, 1.01, 81.0, 3.5, 640.0, 210, 0.5, 1234,
                    "2026-11-05T00:00:00Z",
                ),
            )
            conn.execute(
                """
                INSERT INTO reports (
                    uuid, created_at, provider_slug, plan_slug, provider_name,
                    plan_name, claimed_model, harness_type, quota_window_stage,
                    verification_mode, key_dedup_hash, csl_index, raw_jsd, net_jsd,
                    split_jsd, tail_ratio, nearest_profile, second_profile,
                    token_ratio, cache_hit_pct, compression_pct, tps, ttft_ms,
                    rate_429_pct, observed_dist_json, baseline_dist_json,
                    nearest_ranking_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy-report-uuid-1", "2026-11-05T01:02:03Z", "legacy-provider",
                    "legacy-plan", "Legacy Provider", "Legacy Plan", "legacy-model-x",
                    "unknown", "window_early (<30%)", "Simulated · 模拟生成",
                    "deadbeefcafe", 88.5, 0.015, 0.012, 0.02, 1.25, "profile-a",
                    "profile-b", 1.01, 81.0, 3.5, 640.0, 210, 0.5, "{}", "{}", "[]",
                ),
            )
            conn.execute(
                """
                INSERT INTO timeline_series (
                    provider_slug, plan_slug, bucket_type, bucket_label, seq_order,
                    csl_index, net_jsd, tps, rate_429_pct, sample_count
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    "legacy-provider", "legacy-plan", "day", "2026-11-05", 1,
                    88.5, 0.012, 640.0, 0.5, 321,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def _columns(self, conn, table: str) -> set:
        return {row[1] for row in conn.execute(f"PRAGMA table_info({table})")}

    def _assert_migrated(self, db_path: str):
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            self.assertIn("verified_sample_count", self._columns(conn, "plans"))
            self.assertIn("data_origin", self._columns(conn, "plans"))
            self.assertIn("data_origin", self._columns(conn, "reports"))
            self.assertIn("data_origin", self._columns(conn, "timeline_series"))

            # Legacy rows survive untouched apart from the new-column defaults
            plan = conn.execute(
                "SELECT * FROM plans WHERE provider_slug = 'legacy-provider'"
            ).fetchone()
            self.assertIsNotNone(plan)
            self.assertEqual(plan["plan_name"], "Legacy Plan")
            self.assertEqual(plan["csl_index_7d"], 88.5)
            self.assertEqual(plan["sample_count_7d"], 1234)
            self.assertEqual(plan["data_origin"], "Simulated-Demo")
            self.assertEqual(plan["verified_sample_count"], 0)

            report = conn.execute(
                "SELECT * FROM reports WHERE uuid = 'legacy-report-uuid-1'"
            ).fetchone()
            self.assertIsNotNone(report)
            self.assertEqual(report["data_origin"], "Simulated-Demo")

            series = conn.execute(
                "SELECT * FROM timeline_series WHERE provider_slug = 'legacy-provider'"
            ).fetchone()
            self.assertIsNotNone(series)
            self.assertEqual(series["sample_count"], 321)
            self.assertEqual(series["data_origin"], "Simulated-Demo")

            # No seeding or duplication disturbed the legacy rows
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM plans").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM reports").fetchone()[0], 1)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM timeline_series").fetchone()[0], 1
            )
        finally:
            conn.close()

    def test_06_legacy_v1_schema_migrates_on_open(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "legacy_v1.db")
            self._build_v1_db(db_path)

            # Sanity: the fixture really is a pre-migration database
            conn = sqlite3.connect(db_path)
            try:
                self.assertNotIn("data_origin", self._columns(conn, "plans"))
                self.assertNotIn("verified_sample_count", self._columns(conn, "plans"))
            finally:
                conn.close()

            # First open runs the startup migration
            csl_engine.CSLDatabase(db_path)
            self._assert_migrated(db_path)

            # Second open is idempotent: no error, same end state
            csl_engine.CSLDatabase(db_path)
            self._assert_migrated(db_path)

    def test_09_probe_report_fields_intact_on_migrated_schema(self):
        """v1.3.4: positional INSERTs silently corrupt reports on migrated DBs.

        A migrated reports table carries data_origin LAST (ALTER TABLE
        appends), not at position 11 as in a fresh CREATE TABLE. The old
        positional INSERT INTO reports VALUES(...) therefore shifted every
        value from column 11 on by one slot: the second 'Server-Verified'
        landed in key_dedup_hash, the hash in csl_index, the 429 rate in
        ttft_ms, and the ranking JSON in data_origin (production-verified
        2026-11-06; the four live reports were repaired by hand). All
        INSERTs are named-column now; this test proves a probe report
        written into a migrated-form database lands field-perfect.
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "migrated_probe.db")
            self._build_v1_db(db_path)

            # Add a probe-able catalog plan (whitelisted provider whose
            # claimed model has a golden baseline) in the v1 plans shape.
            plan_meta = next(
                x for x in csl_engine.INITIAL_PLANS
                if x["provider_slug"] == "volcengine"
                and x["plan_slug"] == "coding-plan-lite"
            )
            conn = sqlite3.connect(db_path)
            try:
                conn.execute(
                    """
                    INSERT INTO plans (
                        provider_slug, plan_slug, provider_name, plan_name, category,
                        price_label, claimed_model, harness_type, csl_index_7d, csl_iqr,
                        net_jsd, jsd_std, split_jsd, tail_ratio, nearest_profile,
                        second_profile, peak_delta_csl, token_ratio, cache_hit_pct,
                        compression_pct, median_tps, ttft_ms, rate_429_pct,
                        sample_count_7d, updated_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        plan_meta["provider_slug"], plan_meta["plan_slug"],
                        plan_meta["provider_name"], plan_meta["plan_name"],
                        plan_meta["category"], plan_meta["price_label"],
                        plan_meta["claimed_model"], plan_meta["harness_type"],
                        plan_meta["csl_index_7d"], plan_meta["csl_iqr"],
                        plan_meta["net_jsd"], plan_meta["jsd_std"],
                        plan_meta["split_jsd"], plan_meta["tail_ratio"],
                        plan_meta["nearest_profile"], plan_meta["second_profile"],
                        plan_meta["peak_delta_csl"], plan_meta["token_ratio"],
                        plan_meta["cache_hit_pct"], plan_meta["compression_pct"],
                        plan_meta["median_tps"], plan_meta["ttft_ms"],
                        plan_meta["rate_429_pct"], plan_meta["sample_count_7d"],
                        "2026-11-05T00:00:00Z",
                    ),
                )
                conn.commit()
                # Pre-migration shape: 27 report columns, no data_origin
                cols_before = [r[1] for r in conn.execute("PRAGMA table_info(reports)")]
                self.assertEqual(len(cols_before), 27)
                self.assertNotIn("data_origin", cols_before)
            finally:
                conn.close()

            upstream = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
            threading.Thread(target=upstream.serve_forever, daemon=True).start()
            saved_base = csl_engine._TEST_UPSTREAM_BASE_URL
            csl_engine._TEST_UPSTREAM_BASE_URL = (
                f"http://127.0.0.1:{upstream.server_address[1]}"
            )
            try:
                # Opening the engine runs the startup migration: data_origin
                # is APPENDED to reports (slot 28), unlike a fresh table.
                db = csl_engine.CSLDatabase(db_path)
                conn = sqlite3.connect(db_path)
                try:
                    cols_after = [r[1] for r in conn.execute("PRAGMA table_info(reports)")]
                finally:
                    conn.close()
                self.assertEqual(len(cols_after), 28)
                self.assertEqual(cols_after[-1], "data_origin")

                report = db.record_probe_submission(
                    {
                        "provider_slug": "volcengine",
                        "plan_slug": "coding-plan-lite",
                        "api_key": "sk-STUB-GOOD-KEY-0001",
                    }
                )
                self.assertIsNotNone(report)
            finally:
                csl_engine._TEST_UPSTREAM_BASE_URL = saved_base
                upstream.shutdown()
                upstream.server_close()

            # Field sanity on the row as STORED (raw sqlite, named access).
            # On the old positional INSERT this query finds ZERO rows: the
            # ranking JSON sat in data_origin instead of 'Server-Verified'.
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            try:
                rows = conn.execute(
                    "SELECT * FROM reports WHERE data_origin = 'Server-Verified'"
                ).fetchall()
                self.assertEqual(len(rows), 1)
                row = rows[0]
            finally:
                conn.close()

            self.assertEqual(row["verification_mode"], "Server-Verified")
            self.assertIsInstance(row["csl_index"], (int, float))
            self.assertGreaterEqual(row["csl_index"], 0)
            self.assertLessEqual(row["csl_index"], 100)
            self.assertIsInstance(row["rate_429_pct"], (int, float))
            self.assertLessEqual(row["rate_429_pct"], 100)
            ranking = json.loads(row["nearest_ranking_json"])
            self.assertIsInstance(ranking, list)
            self.assertGreaterEqual(len(ranking), 1)
            self.assertTrue(row["nearest_profile"].startswith(ranking[0]["model"]))
            dedup = row["key_dedup_hash"]
            # compute_irreversible_key_hash stores a 16-char truncated
            # SHA-256 hex by design; the stored value must be exactly that
            # hash of the submitted key — on the shifted INSERT it was the
            # csl_index float instead.
            self.assertEqual(
                dedup, csl_engine.compute_irreversible_key_hash("sk-STUB-GOOD-KEY-0001")
            )
            self.assertEqual(len(dedup), 16)
            self.assertTrue(all(ch in "0123456789abcdef" for ch in dedup))
            self.assertIsInstance(json.loads(row["observed_dist_json"]), dict)
            self.assertIsInstance(json.loads(row["baseline_dist_json"]), dict)


if __name__ == "__main__":
    unittest.main()
