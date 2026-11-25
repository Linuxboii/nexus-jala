# nexus-jala

Audit a website's HTTP security headers and get a letter grade with concrete, per-header fixes.

*nexus* (Latin, a binding or bond) + *jala* (Sanskrit, net) - the web of headers that ties a site's defences together.

> Only scan systems you own or are authorized to test.

## Features

- Fetches any URL with `urllib` (follows redirects by default, `--no-follow` to audit the first hop) and audits the response headers - 4xx/5xx responses are audited too.
- Audits a **saved raw headers file** (`curl -sI`, `curl -D`, browser dev-tools copy) or stdin. Redirect chains are handled - the last response block is graded.
- Grades, out of 100 points:

  | Check | Points | What is looked at |
  |---|---|---|
  | Content-Security-Policy | 25 | `unsafe-inline` (unless nonce/hash/`strict-dynamic`), `unsafe-eval`, wildcard/scheme script sources, `object-src`, `base-uri`, `frame-ancestors`, Report-Only-only |
  | Strict-Transport-Security | 15 | plain HTTP, `max-age` (0, < 180 days), `includeSubDomains`, preload eligibility |
  | X-Frame-Options | 10 | `DENY`/`SAMEORIGIN`, deprecated `ALLOW-FROM`, CSP `frame-ancestors` as substitute |
  | X-Content-Type-Options | 10 | `nosniff` |
  | Referrer-Policy | 10 | leaky values (`unsafe-url`, `no-referrer-when-downgrade`), fallback token lists |
  | Permissions-Policy | 5 | presence, deprecated `Feature-Policy` |
  | Cross-Origin-Opener-Policy | 5 | `same-origin`, `same-origin-allow-popups`, `unsafe-none` |
  | Set-Cookie flags | 10 | `Secure`, `HttpOnly`, `SameSite`, `SameSite=None` without `Secure`, `__Host-`/`__Secure-` prefix rules |
  | Information disclosure | 10 | versioned `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-Generator`, ... |

- Informational checks (no points): Cross-Origin-Embedder-Policy / cross-origin isolation, CORS (`*` with credentials, `null` origin).
- Letter grades A+ / A / B / C / D / F, coloured terminal output (auto-disabled for pipes and `NO_COLOR`), `--json` for tooling.
- `--min-grade B` returns exit status 1 when the grade is too low, so it drops straight into CI.
- Zero dependencies - Python 3.10+ standard library only.

## Install

```sh
pip install .
# or run without installing
python -m nexus_jala --help
```

## Usage

```sh
nexus-jala https://example.com
nexus-jala example.com --json
nexus-jala https://staging.internal --insecure --no-follow
curl -sI https://example.com > headers.txt && nexus-jala --file headers.txt
nexus-jala --file headers.txt --min-grade B     # exit 1 if below B
```

Example, auditing the bundled sample file `examples/legacy-app.txt`:

```text
$ nexus-jala --file examples/legacy-app.txt
nexus-jala  examples/legacy-app.txt  (HTTP 200)
Grade: F  (31/100 points)

  FAIL  Content-Security-Policy        7/25  policy enforced, but: 'unsafe-inline' scripts, broad script sources https:
        -> Remove 'unsafe-inline' from script-src; use nonces ('nonce-...') or hashes instead. It negates most XSS protection.
        -> script-src allows https:; list explicit origins instead.
        -> Set object-src 'none' to block plugin content (Flash/Java/embed).
        -> Set base-uri 'none' (or 'self') to prevent <base> tag injection.
        -> Add frame-ancestors 'self' (or 'none') - the modern replacement for X-Frame-Options.
  WARN  Strict-Transport-Security      8/15  max-age=86400 (1 day)
        -> max-age is 86400s (1 day); raise it to at least 15552000 (180 days), ideally 31536000.
        -> Add includeSubDomains so subdomains cannot be downgraded either.
  PASS  X-Frame-Options               10/10  SAMEORIGIN
  FAIL  X-Content-Type-Options         0/10  header missing
        -> Add X-Content-Type-Options: nosniff to stop MIME-type sniffing.
  FAIL  Referrer-Policy                2/10  no-referrer-when-downgrade
        -> 'no-referrer-when-downgrade' can leak full URLs (paths, query strings) to other sites; prefer strict-origin-when-cross-origin.
  FAIL  Permissions-Policy             0/5   header missing
        -> Add Permissions-Policy to disable unused powerful features, e.g. camera=(), microphone=(), geolocation=(), payment=()
  WARN  Cross-Origin-Opener-Policy     0/5   header missing
        -> Add Cross-Origin-Opener-Policy: same-origin to isolate your browsing context from cross-origin popups (mitigates XS-Leaks and Spectre-style attacks).
  INFO  Cross-Origin-Embedder-Policy    -    not set (only needed for cross-origin isolation)
        -> If you need SharedArrayBuffer or high-resolution timers, set COEP: require-corp together with COOP: same-origin.
  FAIL  Set-Cookie flags               2/10  2 cookie(s), 2 with issues
        -> PHPSESSID: add Secure, SameSite=Lax
        -> cart: add Secure, HttpOnly; SameSite=None without Secure is rejected by browsers
  FAIL  Information disclosure         2/10  discloses Server, X-Powered-By
        -> Server header reveals version 'Apache/2.4.29 (Ubuntu)'; strip version details (nginx: server_tokens off; Apache: ServerTokens Prod).
        -> Remove X-Powered-By: PHP/7.2.24
```

JSON output (`--json`) contains `grade`, `score`, `max_score`, `percent`, `status`, `final_url` and a `findings` array with `key`, `header`, `status`, `score`, `max_score`, `summary`, `advice` and the raw `value` for each check.

Exit codes: `0` audited, `1` grade below `--min-grade`, `2` fetch/file error.

## How it works

1. Headers come either from a `GET` request (body is never read) or from a parsed raw header dump. A small case-insensitive multi-map keeps duplicate headers such as `Set-Cookie`.
2. Each check parses its header the way browsers do - e.g. the first duplicate CSP directive wins, the last recognised `Referrer-Policy` token wins, nonces/hashes neutralise `'unsafe-inline'`.
3. Point totals map to grades: A+ >= 95, A >= 85, B >= 70, C >= 55, D >= 40, otherwise F.

HSTS is graded as failed for plain-HTTP responses because browsers ignore it there. When auditing a file, HTTPS is assumed; pass `--assume-http` if the dump came from an `http://` URL.

## Running the tests

```sh
python -m unittest discover -s tests
```

## License

MIT - see [LICENSE](LICENSE).
