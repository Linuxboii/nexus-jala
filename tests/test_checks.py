import unittest

from nexus_jala.headers import HeaderSet, parse_raw
from nexus_jala import checks
from nexus_jala.grader import audit, letter_grade


STRONG = """HTTP/2 200
content-type: text/html
strict-transport-security: max-age=63072000; includeSubDomains; preload
content-security-policy: default-src 'self'; script-src 'self' 'nonce-abc123'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'
x-frame-options: DENY
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin
permissions-policy: camera=(), microphone=(), geolocation=()
cross-origin-opener-policy: same-origin
cross-origin-embedder-policy: require-corp
set-cookie: __Host-sid=abc; Path=/; Secure; HttpOnly; SameSite=Lax
"""

WEAK = """HTTP/1.1 200 OK
Server: Apache/2.4.29 (Ubuntu)
X-Powered-By: PHP/7.2.24
Set-Cookie: PHPSESSID=deadbeef; path=/
Content-Type: text/html
"""


def hs(**kw):
    return HeaderSet([(k.replace("_", "-"), v) for k, v in kw.items()])


class ParseRawTests(unittest.TestCase):
    def test_parses_status_and_multiple_cookies(self):
        text = "HTTP/1.1 200 OK\r\nSet-Cookie: a=1\r\nSet-Cookie: b=2\r\nX-Test: yes\r\n\r\n<html>body: ignored</html>"
        status, headers = parse_raw(text)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get_all("set-cookie"), ["a=1", "b=2"])
        self.assertIsNone(headers.get("html>body"))

    def test_uses_last_block_of_redirect_chain(self):
        text = "HTTP/1.1 301 Moved\nLocation: https://x/\n\nHTTP/2 200\nx-frame-options: DENY\n"
        status, headers = parse_raw(text)
        self.assertEqual(status, 200)
        self.assertEqual(headers.get("X-Frame-Options"), "DENY")
        self.assertNotIn("location", headers)

    def test_headers_without_status_line_and_folding(self):
        status, headers = parse_raw("Content-Security-Policy: default-src 'self';\n  img-src *\n")
        self.assertIsNone(status)
        self.assertEqual(headers.get("content-security-policy"), "default-src 'self'; img-src *")

    def test_empty_input_raises(self):
        with self.assertRaises(ValueError):
            parse_raw("\n\nnot a header line\n")


class CspTests(unittest.TestCase):
    def test_missing_csp_fails(self):
        f = checks.check_csp(hs())
        self.assertEqual((f.status, f.score), ("fail", 0))

    def test_strong_nonce_policy_gets_full_marks(self):
        f = checks.check_csp(hs(content_security_policy="default-src 'self'; script-src 'self' 'nonce-r4nd'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'"))
        self.assertEqual(f.score, f.max_score)
        self.assertEqual(f.status, "pass")

    def test_unsafe_inline_and_eval_penalised(self):
        f = checks.check_csp(hs(content_security_policy="default-src 'self' 'unsafe-inline' 'unsafe-eval'"))
        self.assertLess(f.score, 15)
        joined = " ".join(f.advice)
        self.assertIn("unsafe-inline", joined)
        self.assertIn("unsafe-eval", joined)

    def test_unsafe_inline_ignored_when_nonce_present(self):
        a = checks.check_csp(hs(content_security_policy="script-src 'nonce-x' 'unsafe-inline'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"))
        self.assertEqual(a.score, a.max_score)

    def test_report_only_partial_credit(self):
        f = checks.check_csp(hs(content_security_policy_report_only="default-src 'self'"))
        self.assertEqual(f.status, "warn")
        self.assertGreater(f.score, 0)


class HstsTests(unittest.TestCase):
    def test_plain_http_fails(self):
        f = checks.check_hsts(hs(strict_transport_security="max-age=31536000"), https=False)
        self.assertEqual(f.status, "fail")

    def test_short_max_age_warns(self):
        f = checks.check_hsts(hs(strict_transport_security="max-age=3600"), https=True)
        self.assertEqual(f.status, "warn")

    def test_max_age_zero_fails(self):
        f = checks.check_hsts(hs(strict_transport_security='max-age="0"'), https=True)
        self.assertEqual(f.score, 0)

    def test_full_hsts(self):
        f = checks.check_hsts(hs(strict_transport_security="max-age=31536000; includeSubDomains"), https=True)
        self.assertEqual(f.score, f.max_score)


class OtherHeaderTests(unittest.TestCase):
    def test_xfo_covered_by_frame_ancestors(self):
        f = checks.check_xfo(hs(content_security_policy="frame-ancestors 'none'"))
        self.assertEqual(f.status, "pass")

    def test_xfo_allow_from_deprecated(self):
        f = checks.check_xfo(hs(x_frame_options="ALLOW-FROM https://a.example"))
        self.assertEqual(f.status, "warn")

    def test_nosniff(self):
        self.assertEqual(checks.check_xcto(hs(x_content_type_options="nosniff")).status, "pass")
        self.assertEqual(checks.check_xcto(hs(x_content_type_options="sniff")).status, "fail")

    def test_referrer_policy_last_valid_token_wins(self):
        f = checks.check_referrer(hs(referrer_policy="unsafe-url, no-referrer"))
        self.assertEqual(f.status, "pass")
        self.assertEqual(checks.check_referrer(hs(referrer_policy="unsafe-url")).status, "fail")

    def test_permissions_policy_counts_features(self):
        f = checks.check_permissions(hs(permissions_policy="camera=(), microphone=(), geolocation=(self)"))
        self.assertEqual(f.status, "pass")
        self.assertIn("3", f.summary)

    def test_coop_values(self):
        self.assertEqual(checks.check_coop(hs(cross_origin_opener_policy="same-origin")).score, 5)
        self.assertEqual(checks.check_coop(hs(cross_origin_opener_policy="unsafe-none")).score, 0)

    def test_cors_wildcard_with_credentials_flagged(self):
        f = checks.check_cors(hs(access_control_allow_origin="*", access_control_allow_credentials="true"))
        self.assertEqual(f.status, "warn")
        self.assertIsNone(checks.check_cors(hs()))


class CookieTests(unittest.TestCase):
    def test_parse_cookie_attributes(self):
        c = checks.parse_set_cookie("sid=1; Path=/; Secure; HttpOnly; SameSite=Strict")
        self.assertEqual(c["name"], "sid")
        self.assertTrue(c["secure"])
        self.assertTrue(c["httponly"])
        self.assertEqual(c["samesite"], "strict")

    def test_insecure_cookie_lists_missing_flags(self):
        f = checks.check_cookies(hs(set_cookie="sid=1; Path=/"), https=True)
        self.assertEqual(f.status, "fail")
        joined = " ".join(f.advice)
        for flag in ("Secure", "HttpOnly", "SameSite"):
            self.assertIn(flag, joined)

    def test_samesite_none_requires_secure(self):
        f = checks.check_cookies(hs(set_cookie="t=1; HttpOnly; SameSite=None"), https=True)
        self.assertIn("SameSite=None", " ".join(f.advice))

    def test_host_prefix_rules(self):
        f = checks.check_cookies(hs(set_cookie="__Host-x=1; Secure; HttpOnly; SameSite=Lax; Domain=example.com; Path=/"), https=True)
        self.assertIn("__Host-", " ".join(f.advice))

    def test_no_cookies_is_pass(self):
        f = checks.check_cookies(hs(), https=True)
        self.assertEqual((f.status, f.score), ("pass", f.max_score))


class LeakTests(unittest.TestCase):
    def test_versioned_server_and_powered_by_deducted(self):
        f = checks.check_leaks(hs(server="nginx/1.18.0", x_powered_by="Express"))
        self.assertLess(f.score, f.max_score)
        self.assertIn("nginx/1.18.0", " ".join(f.advice))

    def test_bare_server_name_not_penalised(self):
        f = checks.check_leaks(hs(server="cloudflare"))
        self.assertEqual(f.score, f.max_score)


class GradeTests(unittest.TestCase):
    def test_letter_boundaries(self):
        self.assertEqual(letter_grade(100), "A+")
        self.assertEqual(letter_grade(85), "A")
        self.assertEqual(letter_grade(70), "B")
        self.assertEqual(letter_grade(55), "C")
        self.assertEqual(letter_grade(40), "D")
        self.assertEqual(letter_grade(39), "F")

    def test_strong_site_scores_a_plus(self):
        _, headers = parse_raw(STRONG)
        report = audit(headers, target="fixture", https=True, status=200)
        self.assertEqual(report.grade, "A+", [(f.key, f.score) for f in report.findings])

    def test_weak_site_scores_f(self):
        _, headers = parse_raw(WEAK)
        report = audit(headers, target="fixture", https=True, status=200)
        self.assertEqual(report.grade, "F")
        self.assertEqual(report.to_dict()["grade"], "F")
        self.assertEqual(report.max_score, 100)


if __name__ == "__main__":
    unittest.main()
