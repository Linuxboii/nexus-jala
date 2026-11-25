import io
import json
import os
import tempfile
import unittest
import urllib.error
from contextlib import redirect_stderr, redirect_stdout
from email.message import Message
from unittest import mock

from nexus_jala import cli, fetch


class FakeResponse:
    def __init__(self, url, status, pairs):
        self._url = url
        self.status = status
        self.headers = Message()
        for k, v in pairs:
            self.headers[k] = v
        self.closed = False

    def geturl(self):
        return self._url

    def close(self):
        self.closed = True


class FakeOpener:
    def __init__(self, result):
        self.result = result
        self.requests = []

    def open(self, request, timeout=None):
        self.requests.append(request)
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


class FetchTests(unittest.TestCase):
    def test_bare_host_gets_https(self):
        self.assertEqual(fetch.normalise_url("example.com"), "https://example.com")
        self.assertEqual(fetch.normalise_url("http://x"), "http://x")

    def test_fetch_collects_duplicate_headers(self):
        resp = FakeResponse("https://site.test/home", 200, [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
        opener = FakeOpener(resp)
        with mock.patch.object(fetch.urllib.request, "build_opener", return_value=opener):
            result = fetch.fetch_headers("site.test")
        self.assertEqual(result.status, 200)
        self.assertTrue(result.https)
        self.assertEqual(result.headers.get_all("set-cookie"), ["a=1", "b=2"])
        self.assertTrue(resp.closed)
        self.assertEqual(opener.requests[0].full_url, "https://site.test")

    def test_http_error_still_audited(self):
        hdrs = Message()
        hdrs["X-Frame-Options"] = "DENY"
        err = urllib.error.HTTPError("http://site.test/", 404, "Not Found", hdrs, None)
        with mock.patch.object(fetch.urllib.request, "build_opener", return_value=FakeOpener(err)):
            result = fetch.fetch_headers("http://site.test/")
        self.assertEqual(result.status, 404)
        self.assertFalse(result.https)
        self.assertEqual(result.headers.get("x-frame-options"), "DENY")


class CliTests(unittest.TestCase):
    def setUp(self):
        fd, self.path = tempfile.mkstemp(suffix=".txt")
        with os.fdopen(fd, "w") as fh:
            fh.write("HTTP/1.1 200 OK\nX-Content-Type-Options: nosniff\nServer: nginx/1.25.3\n")

    def tearDown(self):
        os.unlink(self.path)

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = cli.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_file_json_output(self):
        code, out, _ = self.run_cli("--file", self.path, "--json")
        self.assertEqual(code, 0)
        data = json.loads(out)
        self.assertEqual(data["status"], 200)
        keys = {f["key"] for f in data["findings"]}
        self.assertTrue({"csp", "hsts", "xcto", "cookies", "leaks"} <= keys)

    def test_text_output_and_min_grade_exit_code(self):
        code, out, err = self.run_cli("--file", self.path, "--min-grade", "B")
        self.assertEqual(code, 1)
        self.assertIn("Grade: F", out)
        self.assertIn("X-Content-Type-Options", out)
        self.assertNotIn("\033[", out)
        self.assertIn("below the required minimum", err)

    def test_missing_file_is_error_2(self):
        code, _, err = self.run_cli("--file", self.path + ".missing")
        self.assertEqual(code, 2)
        self.assertIn("error", err)

    def test_live_url_uses_fetch(self):
        result = fetch.FetchResult("https://a.test", "https://a.test/", 200,
                                   fetch.HeaderSet([("Strict-Transport-Security", "max-age=31536000")]))
        with mock.patch.object(cli, "fetch_headers", return_value=result) as fh:
            code, out, _ = self.run_cli("a.test", "--json")
        fh.assert_called_once()
        data = json.loads(out)
        hsts = next(f for f in data["findings"] if f["key"] == "hsts")
        self.assertEqual(hsts["status"], "warn")
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
