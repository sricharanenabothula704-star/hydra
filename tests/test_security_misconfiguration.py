from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import threading
import tempfile
import unittest

from core.security_misconfiguration import SecurityMisconfigurationScanner


class HeaderOnlyHandler(BaseHTTPRequestHandler):
    seen = []

    def do_HEAD(self):
        type(self).seen.append(self.command)
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass


class SecurityMisconfigurationTests(unittest.TestCase):
    def test_sends_one_head_and_does_not_follow_redirects(self):
        with tempfile.TemporaryDirectory() as tmp:
            allowlist = Path(tmp) / "scope.txt"
            allowlist.write_text("localhost\n", encoding="utf-8")
            server = HTTPServer(("127.0.0.1", 0), HeaderOnlyHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                HeaderOnlyHandler.seen.clear()
                url = f"http://localhost:{server.server_port}/ignored-path"
                result = SecurityMisconfigurationScanner(allowlist_path=allowlist).scan(
                    url
                )
                self.assertEqual(result["requests_sent"], 1)
                self.assertEqual(result["redirects_followed"], 0)
                self.assertEqual(HeaderOnlyHandler.seen, ["HEAD"])
                self.assertTrue(result["findings"])
            finally:
                server.shutdown()
                server.server_close()

    def test_out_of_scope_target_is_rejected_before_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            allowlist = Path(tmp) / "scope.txt"
            allowlist.write_text("*.example.com\n", encoding="utf-8")
            scanner = SecurityMisconfigurationScanner(allowlist_path=allowlist)
            with self.assertRaises(PermissionError):
                scanner.scan("http://notexample.com")

    def test_non_http_scheme_is_rejected_before_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            allowlist = Path(tmp) / "scope.txt"
            allowlist.write_text("localhost\n", encoding="utf-8")
            scanner = SecurityMisconfigurationScanner(allowlist_path=allowlist)
            with self.assertRaises(ValueError):
                scanner.scan("ftp://localhost:21")


if __name__ == "__main__":
    unittest.main()
