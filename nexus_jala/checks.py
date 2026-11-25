"""Individual security header checks.

Each check returns a :class:`Finding` with a score out of ``max_score``.
The maximum scores add up to 100 so the total reads as a percentage.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .headers import HeaderSet


@dataclass
class Finding:
    key: str
    title: str
    status: str  # pass | warn | fail | info
    score: int
    max_score: int
    summary: str
    advice: list[str] = field(default_factory=list)
    value: str | None = None

    def to_dict(self) -> dict:
        return {
            "key": self.key,
            "header": self.title,
            "status": self.status,
            "score": self.score,
            "max_score": self.max_score,
            "summary": self.summary,
            "advice": list(self.advice),
            "value": self.value,
        }


def _status(score: int, max_score: int) -> str:
    if max_score == 0:
        return "info"
    ratio = score / max_score
    if ratio >= 0.9:
        return "pass"
    if ratio >= 0.4:
        return "warn"
    return "fail"


# --------------------------------------------------------------------------
# Content-Security-Policy
# --------------------------------------------------------------------------

def parse_csp(value: str) -> dict[str, list[str]]:
    """Parse a CSP string into ``{directive: [sources]}``.

    Directive names are lower-cased; per the spec, the first occurrence of a
    duplicated directive wins.
    """
    directives: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.split()
        if not tokens:
            continue
        name = tokens[0].lower()
        if name not in directives:
            directives[name] = tokens[1:]
    return directives


def _lower(tokens: list[str]) -> list[str]:
    return [t.lower() for t in tokens]


CSP_MAX = 25


def check_csp(headers: HeaderSet) -> Finding:
    title = "Content-Security-Policy"
    values = headers.get_all("content-security-policy")
    if not values:
        ro = headers.get("content-security-policy-report-only")
        if ro:
            return Finding(
                "csp", title, "warn", 5, CSP_MAX,
                "only a Report-Only policy is set (nothing is enforced)",
                ["Promote the Report-Only policy to an enforced Content-Security-Policy once violation reports are clean."],
                ro,
            )
        return Finding(
            "csp", title, "fail", 0, CSP_MAX, "header missing",
            ["Add a Content-Security-Policy. A solid starting point: "
             "default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'self'"],
        )

    value = values[0]
    csp = parse_csp(value)
    score = CSP_MAX
    advice: list[str] = []
    notes: list[str] = []

    script = csp.get("script-src", csp.get("default-src"))
    if script is None:
        score -= 10
        notes.append("no script-src/default-src")
        advice.append("Define script-src (or default-src): without it scripts may load from anywhere.")
    else:
        low = _lower(script)
        has_nonce_or_hash = any(t.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-")) for t in low)
        if "'unsafe-inline'" in low and not has_nonce_or_hash and "'strict-dynamic'" not in low:
            score -= 8
            notes.append("'unsafe-inline' scripts")
            advice.append("Remove 'unsafe-inline' from script-src; use nonces ('nonce-...') or hashes instead. "
                          "It negates most XSS protection.")
        if "'unsafe-eval'" in low:
            score -= 5
            notes.append("'unsafe-eval'")
            advice.append("Remove 'unsafe-eval' from script-src; refactor code that relies on eval()/new Function().")
        wild = [t for t in low if t in ("*", "http:", "https:", "data:")]
        if wild and "'strict-dynamic'" not in low:
            score -= 5
            notes.append("broad script sources " + " ".join(sorted(set(wild))))
            advice.append(f"script-src allows {', '.join(sorted(set(wild)))}; list explicit origins instead.")

    obj = csp.get("object-src", csp.get("default-src"))
    if obj is None or _lower(obj) != ["'none'"]:
        score -= 2
        advice.append("Set object-src 'none' to block plugin content (Flash/Java/embed).")
    if "base-uri" not in csp:
        score -= 2
        advice.append("Set base-uri 'none' (or 'self') to prevent <base> tag injection.")
    if "frame-ancestors" not in csp:
        score -= 1
        advice.append("Add frame-ancestors 'self' (or 'none') - the modern replacement for X-Frame-Options.")

    score = max(score, 0)
    if len(values) > 1:
        advice.append(f"{len(values)} CSP headers sent; only the first was analysed (browsers enforce all of them).")
    summary = "policy enforced" if not notes else "policy enforced, but: " + ", ".join(notes)
    return Finding("csp", title, _status(score, CSP_MAX), score, CSP_MAX, summary, advice, value)


# --------------------------------------------------------------------------
# Strict-Transport-Security
# --------------------------------------------------------------------------

HSTS_MAX = 15
SIX_MONTHS = 15552000
ONE_YEAR = 31536000


def _days(seconds: int) -> str:
    days = seconds // 86400
    if days == 0:
        return f"{seconds // 3600} hours"
    return f"{days} day" + ("" if days == 1 else "s")


def check_hsts(headers: HeaderSet, https: bool = True) -> Finding:
    title = "Strict-Transport-Security"
    value = headers.get("strict-transport-security")
    if not https:
        return Finding(
            "hsts", title, "fail", 0, HSTS_MAX, "site served over plain HTTP",
            ["Serve the site over HTTPS, redirect HTTP to HTTPS, then send HSTS from the HTTPS origin "
             "(browsers ignore HSTS received over HTTP)."],
            value,
        )
    if not value:
        return Finding(
            "hsts", title, "fail", 0, HSTS_MAX, "header missing",
            ["Add Strict-Transport-Security: max-age=31536000; includeSubDomains"],
        )
    directives = {}
    for part in value.split(";"):
        k, _, v = part.strip().partition("=")
        if k:
            directives[k.strip().lower()] = v.strip().strip('"')
    raw_age = directives.get("max-age")
    if raw_age is None or not raw_age.isdigit():
        return Finding("hsts", title, "fail", 0, HSTS_MAX, "missing or invalid max-age",
                       ["Specify a numeric max-age, e.g. max-age=31536000."], value)
    age = int(raw_age)
    if age == 0:
        return Finding("hsts", title, "fail", 0, HSTS_MAX, "max-age=0 disables HSTS",
                       ["max-age=0 tells browsers to forget the HSTS policy; set max-age=31536000."], value)
    advice = []
    subdomains = "includesubdomains" in directives
    if age < SIX_MONTHS:
        score = 8
        advice.append(f"max-age is {age}s ({_days(age)}); raise it to at least 15552000 (180 days), ideally 31536000.")
    else:
        score = 13
    if subdomains:
        score += 2
    else:
        advice.append("Add includeSubDomains so subdomains cannot be downgraded either.")
    if "preload" in directives and (not subdomains or age < ONE_YEAR):
        advice.append("The preload directive requires includeSubDomains and max-age >= 31536000 to be accepted by the preload list.")
    summary = f"max-age={age} ({_days(age)})" + ("; includeSubDomains" if subdomains else "") + \
              ("; preload" if "preload" in directives else "")
    return Finding("hsts", title, _status(score, HSTS_MAX), score, HSTS_MAX, summary, advice, value)


# --------------------------------------------------------------------------
# X-Frame-Options
# --------------------------------------------------------------------------

def check_xfo(headers: HeaderSet) -> Finding:
    title, mx = "X-Frame-Options", 10
    value = headers.get("x-frame-options")
    csp_value = headers.get("content-security-policy")
    has_fa = bool(csp_value) and "frame-ancestors" in parse_csp(csp_value)
    if not value:
        if has_fa:
            return Finding("xfo", title, "pass", mx, mx, "not set, but CSP frame-ancestors provides clickjacking protection")
        return Finding("xfo", title, "fail", 0, mx, "header missing (clickjacking possible)",
                       ["Add X-Frame-Options: DENY (or SAMEORIGIN), or CSP frame-ancestors."])
    upper = value.strip().upper()
    if upper in ("DENY", "SAMEORIGIN"):
        return Finding("xfo", title, "pass", mx, mx, upper, [], value)
    if upper.startswith("ALLOW-FROM"):
        if has_fa:
            return Finding("xfo", title, "pass", mx, mx, "ALLOW-FROM (deprecated) backed by CSP frame-ancestors", [], value)
        return Finding("xfo", title, "warn", 4, mx, "ALLOW-FROM is deprecated and ignored by modern browsers",
                       ["Replace ALLOW-FROM with CSP frame-ancestors <origin>."], value)
    return Finding("xfo", title, "fail", 0, mx, f"invalid value '{value}'",
                   ["Use DENY or SAMEORIGIN."], value)


# --------------------------------------------------------------------------
# X-Content-Type-Options
# --------------------------------------------------------------------------

def check_xcto(headers: HeaderSet) -> Finding:
    title, mx = "X-Content-Type-Options", 10
    value = headers.get("x-content-type-options")
    if value is None:
        return Finding("xcto", title, "fail", 0, mx, "header missing",
                       ["Add X-Content-Type-Options: nosniff to stop MIME-type sniffing."])
    if value.strip().lower() == "nosniff":
        return Finding("xcto", title, "pass", mx, mx, "nosniff", [], value)
    return Finding("xcto", title, "fail", 0, mx, f"invalid value '{value}'",
                   ["The only valid value is nosniff."], value)


# --------------------------------------------------------------------------
# Referrer-Policy
# --------------------------------------------------------------------------

REFERRER_SCORES = {
    "no-referrer": 10,
    "same-origin": 10,
    "strict-origin": 10,
    "strict-origin-when-cross-origin": 10,
    "origin": 6,
    "origin-when-cross-origin": 6,
    "no-referrer-when-downgrade": 2,
    "unsafe-url": 0,
}


def check_referrer(headers: HeaderSet) -> Finding:
    title, mx = "Referrer-Policy", 10
    value = headers.get("referrer-policy")
    if not value:
        return Finding("referrer", title, "warn", 5, mx,
                       "header missing (browser default strict-origin-when-cross-origin applies)",
                       ["Set Referrer-Policy: strict-origin-when-cross-origin (or no-referrer) explicitly; "
                        "older browsers default to leaking full URLs."])
    # Browsers use the last token they understand.
    chosen = None
    for token in value.split(","):
        t = token.strip().lower()
        if t in REFERRER_SCORES:
            chosen = t
    if chosen is None:
        return Finding("referrer", title, "fail", 0, mx, f"no recognised policy in '{value}'",
                       ["Use strict-origin-when-cross-origin, same-origin or no-referrer."], value)
    score = REFERRER_SCORES[chosen]
    advice = []
    if score < mx:
        advice.append(f"'{chosen}' can leak full URLs (paths, query strings) to other sites; "
                      "prefer strict-origin-when-cross-origin.")
    return Finding("referrer", title, _status(score, mx), score, mx, chosen, advice, value)


# --------------------------------------------------------------------------
# Permissions-Policy
# --------------------------------------------------------------------------

def check_permissions(headers: HeaderSet) -> Finding:
    title, mx = "Permissions-Policy", 5
    value = headers.get("permissions-policy")
    if value:
        features = [p.split("=", 1)[0].strip() for p in value.split(",") if "=" in p]
        disabled = [p.split("=", 1)[0].strip() for p in value.split(",")
                    if "=" in p and p.split("=", 1)[1].strip() == "()"]
        summary = f"{len(features)} features controlled ({len(disabled)} fully disabled)"
        return Finding("permissions", title, "pass", mx, mx, summary, [], value)
    legacy = headers.get("feature-policy")
    if legacy:
        return Finding("permissions", title, "warn", 2, mx, "only the deprecated Feature-Policy header is set",
                       ["Migrate Feature-Policy to Permissions-Policy (syntax: camera=(), geolocation=(self))."], legacy)
    return Finding("permissions", title, "fail", 0, mx, "header missing",
                   ["Add Permissions-Policy to disable unused powerful features, e.g. "
                    "camera=(), microphone=(), geolocation=(), payment=()"])


# --------------------------------------------------------------------------
# Cross-Origin-Opener-Policy / Cross-Origin-Embedder-Policy
# --------------------------------------------------------------------------

def check_coop(headers: HeaderSet) -> Finding:
    title, mx = "Cross-Origin-Opener-Policy", 5
    value = headers.get("cross-origin-opener-policy")
    if not value:
        return Finding("coop", title, "warn", 0, mx, "header missing",
                       ["Add Cross-Origin-Opener-Policy: same-origin to isolate your browsing context "
                        "from cross-origin popups (mitigates XS-Leaks and Spectre-style attacks)."])
    v = value.split(";")[0].strip().lower()
    scores = {"same-origin": 5, "same-origin-allow-popups": 4, "noopener-allow-popups": 4, "unsafe-none": 0}
    if v not in scores:
        return Finding("coop", title, "fail", 0, mx, f"invalid value '{value}'",
                       ["Use same-origin or same-origin-allow-popups."], value)
    score = scores[v]
    advice = []
    if v == "unsafe-none":
        advice.append("unsafe-none disables isolation; use same-origin (or same-origin-allow-popups if you rely on OAuth popups).")
    elif score < mx:
        advice.append("same-origin gives the strongest isolation if popups do not need a window.opener reference.")
    return Finding("coop", title, _status(score, mx), score, mx, v, advice, value)


def check_coep(headers: HeaderSet) -> Finding:
    title = "Cross-Origin-Embedder-Policy"
    value = headers.get("cross-origin-embedder-policy")
    if not value:
        return Finding("coep", title, "info", 0, 0, "not set (only needed for cross-origin isolation)",
                       ["If you need SharedArrayBuffer or high-resolution timers, set COEP: require-corp "
                        "together with COOP: same-origin."])
    v = value.split(";")[0].strip().lower()
    coop = (headers.get("cross-origin-opener-policy") or "").split(";")[0].strip().lower()
    if v in ("require-corp", "credentialless"):
        if coop == "same-origin":
            return Finding("coep", title, "info", 0, 0, f"{v} - page is cross-origin isolated", [], value)
        return Finding("coep", title, "info", 0, 0, f"{v} (pair with COOP same-origin for cross-origin isolation)", [], value)
    return Finding("coep", title, "info", 0, 0, f"'{value}' does not enable isolation", [], value)


# --------------------------------------------------------------------------
# Cookies
# --------------------------------------------------------------------------

def parse_set_cookie(value: str) -> dict:
    parts = [p.strip() for p in value.split(";")]
    name, _, _ = parts[0].partition("=")
    info = {"name": name.strip(), "secure": False, "httponly": False,
            "samesite": None, "domain": None, "path": None}
    for attr in parts[1:]:
        k, _, v = attr.partition("=")
        k = k.strip().lower()
        if k == "secure":
            info["secure"] = True
        elif k == "httponly":
            info["httponly"] = True
        elif k == "samesite":
            info["samesite"] = v.strip().lower() or None
        elif k == "domain":
            info["domain"] = v.strip()
        elif k == "path":
            info["path"] = v.strip()
    return info


COOKIE_MAX = 10


def check_cookies(headers: HeaderSet, https: bool = True) -> Finding:
    title = "Set-Cookie flags"
    raw = headers.get_all("set-cookie")
    if not raw:
        return Finding("cookies", title, "pass", COOKIE_MAX, COOKIE_MAX, "no cookies set")
    total = 0.0
    advice = []
    flagged = 0
    for value in raw:
        c = parse_set_cookie(value)
        points = 1.0
        missing = []
        problems = []
        if not c["secure"]:
            points -= 0.4
            missing.append("Secure")
        if not c["httponly"]:
            points -= 0.3
            missing.append("HttpOnly")
        if c["samesite"] is None:
            points -= 0.2
            missing.append("SameSite=Lax")
        elif c["samesite"] == "none" and not c["secure"]:
            points -= 0.3
            problems.append("SameSite=None without Secure is rejected by browsers")
        elif c["samesite"] not in ("lax", "strict", "none"):
            points -= 0.2
            problems.append(f"unknown SameSite value '{c['samesite']}'")
        if c["name"].startswith("__Host-") and (not c["secure"] or c["domain"] or c["path"] != "/"):
            points -= 0.2
            problems.append("__Host- prefix requires Secure, Path=/ and no Domain")
        elif c["name"].startswith("__Secure-") and not c["secure"]:
            problems.append("__Secure- prefix requires Secure")
        points = max(points, 0.0)
        total += points
        if missing or problems:
            flagged += 1
            msg = f"{c['name'] or '(unnamed)'}: "
            bits = []
            if missing:
                bits.append("add " + ", ".join(missing))
            bits.extend(problems)
            advice.append(msg + "; ".join(bits))
    score = round(COOKIE_MAX * total / len(raw))
    if not https and any(parse_set_cookie(v)["secure"] is False for v in raw):
        advice.append("Cookies are sent over plain HTTP; serve the site over HTTPS.")
    summary = f"{len(raw)} cookie(s), {flagged} with issues"
    status = _status(score, COOKIE_MAX)
    if flagged and status == "pass":
        status = "warn"
    return Finding("cookies", title, status, score, COOKIE_MAX, summary, advice)


# --------------------------------------------------------------------------
# Information leakage
# --------------------------------------------------------------------------

LEAK_HEADERS = {
    "X-Powered-By": 4,
    "X-AspNet-Version": 3,
    "X-AspNetMvc-Version": 3,
    "X-Generator": 2,
    "X-Drupal-Cache": 1,
    "X-Runtime": 1,
}


def check_leaks(headers: HeaderSet) -> Finding:
    title, mx = "Information disclosure", 10
    score = mx
    advice = []
    found = []
    server = headers.get("server")
    if server:
        if re.search(r"\d", server):
            score -= 4
            found.append("Server")
            advice.append(f"Server header reveals version '{server}'; strip version details "
                          "(nginx: server_tokens off; Apache: ServerTokens Prod).")
    for name, cost in LEAK_HEADERS.items():
        value = headers.get(name)
        if value:
            score -= cost
            found.append(name)
            advice.append(f"Remove {name}: {value}")
    score = max(score, 0)
    if not found:
        summary = "no version or technology disclosure" + (f" (Server: {server})" if server else "")
        return Finding("leaks", title, "pass", mx, mx, summary)
    return Finding("leaks", title, _status(score, mx), score, mx, "discloses " + ", ".join(found), advice)


# --------------------------------------------------------------------------
# CORS (informational)
# --------------------------------------------------------------------------

def check_cors(headers: HeaderSet) -> Finding | None:
    origin = headers.get("access-control-allow-origin")
    if origin is None:
        return None
    title = "Access-Control-Allow-Origin"
    creds = (headers.get("access-control-allow-credentials") or "").strip().lower() == "true"
    o = origin.strip()
    if o == "*" and creds:
        return Finding("cors", title, "warn", 0, 0, "wildcard origin combined with credentials",
                       ["Browsers reject '*' with credentials; this often indicates a misconfigured "
                        "or origin-reflecting CORS setup. Allow-list explicit origins."], origin)
    if o.lower() == "null":
        return Finding("cors", title, "warn", 0, 0, "allows the 'null' origin",
                       ["The null origin can be forged from sandboxed iframes; never allow-list it."], origin)
    if o == "*":
        return Finding("cors", title, "info", 0, 0, "any origin may read responses (fine for public, unauthenticated data)",
                       [], origin)
    return Finding("cors", title, "info", 0, 0, f"allows {o}" + (" with credentials" if creds else ""), [], origin)
