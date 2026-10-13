"""Tests for :mod:`core.tool_guard`.

These exist because argv parsing is where security controls quietly rot. The
cases below are the ones that were wrong at least once during development:

* ``-p 80 443 example.com`` denied on ``443`` (flag values treated as targets),
* every URL was silently dropped (the URL regex was ``$``-anchored),
* ``-u`` was classified as a *username* flag, discarding the only host present,
* ``-severity high`` denied on ``high`` (single-dash long options unmatched),
* bare CIDRs were rejected as filesystem paths before the address check ran,
* bracketed IPv6 truncated to ``[`` at the first colon.

Every guarded tool invocation must resolve a target or be explicitly
informational. "No target found" is a denial, because an argv parser that
cannot recognise a target would otherwise be a bypass.
"""

from __future__ import annotations

import pathlib
import sys
import tempfile
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from core.tool_guard import (  # noqa: E402
    GUARDED_TOOLS,
    extract_targets,
    guard_argv,
    should_interpose,
)


class ToolGuardTest(unittest.TestCase):
    allowlist: pathlib.Path
    tmp: tempfile.TemporaryDirectory

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.TemporaryDirectory()
        base = pathlib.Path(cls.tmp.name)
        cls.allowlist = base / "SCOPE_ALLOWLIST.txt"
        cls.allowlist.write_text("example.com\n*.cloud.com\n", encoding="utf-8")
        cls.ok_list = base / "ok_hosts.txt"
        cls.ok_list.write_text("example.com\napi.cloud.com\n", encoding="utf-8")
        cls.bad_list = base / "bad_hosts.txt"
        cls.bad_list.write_text("example.com\nevil.com\n", encoding="utf-8")
        cls.empty_list = base / "empty_hosts.txt"
        cls.empty_list.write_text("# only a comment\n", encoding="utf-8")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.tmp.cleanup()

    # -- helpers ---------------------------------------------------------
    def assertAllowed(self, argv) -> None:
        allowed, reason = guard_argv(argv, self.allowlist)
        self.assertTrue(allowed, f"expected ALLOW for {argv}: {reason}")

    def assertDenied(self, argv) -> None:
        allowed, reason = guard_argv(argv, self.allowlist)
        self.assertFalse(allowed, f"expected DENY for {argv}: {reason}")

    # -- regression cases that were previously wrong -----------------------
    def test_port_values_are_not_targets(self):
        # Regression: -p 80 443 example.com denied on "443".
        self.assertAllowed(["-sV", "-p", "80", "443", "example.com"])

    def test_urls_are_extracted(self):
        # Regression: the URL branch was $-anchored, so any URL with a path was
        # dropped and sqlmap -u https://evil.com/x silently passed.
        targets, _ = extract_targets(["-u", "https://example.com/x?id=1", "--batch"])
        self.assertEqual(targets, ["example.com"])
        self.assertDenied(["-u", "https://evil.com/x"])

    def test_dash_u_is_a_target_flag_not_username(self):
        # Regression: -u was in the non-target value list, discarding the only
        # host on the command line.
        self.assertAllowed(["-u", "https://example.com/login"])
        self.assertDenied(["-u", "https://evil.com/login"])

    def test_single_dash_long_options_are_matched(self):
        # Regression: -severity high denied on "high".
        self.assertAllowed(["-severity", "high", "-u", "example.com"])
        self.assertAllowed(["-top-ports", "100", "example.com"])
        self.assertAllowed(["--rate", "1500", "example.com"])

    def test_template_and_wordlist_paths_are_not_targets(self):
        self.assertAllowed(["-t", "/tmp/tpl/x.yaml", "-u", "example.com"])
        self.assertAllowed(
            ["-w", "/usr/share/wordlist.txt", "-u", "https://example.com/FUZZ"]
        )

    def test_cidr_is_extracted_and_judged(self):
        # Regression: CIDRs were rejected as filesystem paths before the
        # address check could run.
        targets, _ = extract_targets(["10.0.0.0/24"])
        self.assertEqual(targets, ["10.0.0.0/24"])
        self.assertDenied(["10.0.0.0/24"])

    def test_public_cidr_denied_because_not_allowlisted(self):
        # The allowlist is hostname-based, so an unlisted range is denied
        # whether or not it is routable. This is what stops mass-scan ranges.
        self.assertDenied(["8.8.8.0/24"])

    def test_bracketed_ipv6_is_extracted(self):
        # Regression: urlhost excluded ":", so [::1]:8080 truncated to "[".
        targets, _ = extract_targets(["-u", "http://[::1]:8080/"])
        self.assertEqual(targets, ["[::1]"])
        self.assertDenied(["-u", "http://[::1]:8080/"])

    # -- fail-closed on unparseable invocations ---------------------------
    def test_no_target_is_a_denial(self):
        # The core property. Without this, any parsing gap is a bypass.
        self.assertDenied(["quick", "brown", "fox"])
        self.assertDenied([])

    def test_informational_invocations_are_allowed(self):
        self.assertAllowed(["--version"])
        self.assertAllowed(["-h"])
        self.assertAllowed(["-V"])

    # -- list-file handling ----------------------------------------------
    def test_list_file_in_scope(self):
        self.assertAllowed(["-l", str(self.ok_list)])
        self.assertAllowed(["-list", str(self.ok_list), "-top-ports", "100"])

    def test_list_file_out_of_scope_denied(self):
        self.assertDenied(["-l", str(self.bad_list)])

    def test_unreadable_list_denied(self):
        self.assertDenied(
            ["-l", str(pathlib.Path(self.tmp.name) / "does-not-exist.txt")]
        )

    def test_empty_list_denied(self):
        # A list that parses but yields no hosts would run the tool unscoped.
        self.assertDenied(["-l", str(self.empty_list)])

    # -- scope correctness ------------------------------------------------
    def test_lookalike_host_denied(self):
        self.assertDenied(["-u", "https://example.com.attacker.net"])
        self.assertDenied(["example.com.evil.net"])

    def test_userinfo_trick_uses_real_host(self):
        self.assertDenied(["-u", "http://user@evil.com/"])

    def test_url_parser_differential_via_backslash_is_denied(self):
        # "http://evil.com\\@example.com" parses as host "example.com" for a
        # strict parser and host "evil.com" for a lenient one. The guard cannot
        # know which parser the downstream tool uses, so userinfo yields no
        # target and the invocation fails closed.
        for token in (
            "http://evil.com\\@example.com",
            "http://evil.com%5c@example.com",
            "http://evil.com\\\\@example.com",
        ):
            with self.subTest(token=token):
                self.assertDenied(["-u", token])

    def test_help_flag_cannot_smuggle_a_target(self):
        # Informational status requires the whole vector to be informational,
        # so a help flag alongside a real target does not bypass the gate.
        self.assertDenied(["--version", "-u", "evil.com"])
        self.assertDenied(["-h", "evil.com"])

    def test_inline_equals_form(self):
        self.assertDenied(["-u=https://evil.com"])

    def test_mixed_command_line_denies_on_the_out_of_scope_host(self):
        self.assertDenied(["example.com", "evil.com"])

    def test_wildcard_allowlist_rule(self):
        self.assertAllowed(["-u", "https://onboarding.cloud.com"])
        self.assertDenied(["-u", "https://onboarding.cloud.com.evil.net"])

    def test_wildcard_target_is_reduced_to_reg_name(self):
        self.assertAllowed(["-u", "*.example.com"])

    def test_port_suffix_is_stripped(self):
        self.assertAllowed(["-u", "https://example.com:8443/admin"])

    # -- address policy ---------------------------------------------------
    def test_cloud_metadata_denied(self):
        self.assertDenied(["-u", "http://169.254.169.254/latest/meta-data/"])

    def test_private_and_loopback_denied(self):
        self.assertDenied(["-u", "https://192.168.1.1/"])
        self.assertDenied(["-u", "https://10.0.0.5:8080/"])
        self.assertDenied(["-u", "http://localhost:8080"])
        self.assertDenied(["-u", "http://127.0.0.1:9200/"])

    def test_private_opt_out_is_documented_env(self):
        import os

        previous = os.environ.get("HYDRA_ALLOW_PRIVATE")
        os.environ["HYDRA_ALLOW_PRIVATE"] = "1"
        try:
            # Still denied: opting out of the address check does not put a
            # private address into a hostname allowlist.
            self.assertDenied(["-u", "https://192.168.1.1/"])
        finally:
            if previous is None:
                os.environ.pop("HYDRA_ALLOW_PRIVATE", None)
            else:
                os.environ["HYDRA_ALLOW_PRIVATE"] = previous

    def test_proxy_host_is_checked_as_a_target(self):
        # Traffic goes to the proxy, not to the named target, so the proxy host
        # is checked in its own right. A loopback proxy is denied as a literal
        # address; an external one is denied because it is not allowlisted.
        self.assertDenied(["-x", "socks5://127.0.0.1:9050", "-u", "example.com"])
        self.assertDenied(["-x", "http://evil-proxy.net:8080", "-u", "example.com"])
        self.assertDenied(
            ["--proxy", "socks5://evil-proxy.net:1080", "-u", "example.com"]
        )

    # -- ways a tool reaches a host without it being the target argument ----
    # Each of these is a documented route to an unscanned target. They are the
    # cases that make argv guarding an arms race rather than a boundary, so they
    # are pinned here; anything that regresses must fail loudly.

    def _write(self, name: str, lines: list[str]) -> str:
        path = pathlib.Path(self.tmp.name) / name
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return str(path)

    def test_request_file_host_header_is_checked(self):
        # sqlmap -r / ffuf -request: the host lives in a Host: header, never in
        # an argument. The document scanner must find it.
        bad = self._write(
            "req_bad.txt",
            [
                "POST /admin HTTP/1.1",
                "Host: evil.com",
                "User-Agent: curl",
            ],
        )
        good = self._write(
            "req_ok.txt",
            [
                "POST /admin HTTP/1.1",
                "Host: example.com",
                "User-Agent: curl",
            ],
        )
        self.assertDenied(["-r", bad])
        self.assertDenied(["-request", bad])
        self.assertAllowed(["-r", good])
        # Absolute request URI rather than a Host header.
        uri = self._write("req_uri.txt", ["GET https://evil.com/admin HTTP/1.1"])
        self.assertDenied(["-r", uri])

    def test_missing_request_file_denied(self):
        self.assertDenied(["-r", str(pathlib.Path(self.tmp.name) / "nope.txt")])

    def test_config_file_targets_are_checked(self):
        # nuclei -c: a profile embeds targets in YAML. Previously the config was
        # skipped as a non-target flag value, so its targets were never checked
        # -- a config plus an in-scope -u bypassed the gate entirely.
        bad = self._write(
            "bad.yaml",
            [
                "targets:",
                "  - https://evil.com/login",
                "  - https://other-evil.net/",
            ],
        )
        good = self._write("good.yaml", ["targets:", "  - https://example.com/login"])
        self.assertDenied(["-c", bad])
        self.assertDenied(["-c", bad, "-u", "example.com"])
        self.assertAllowed(["-c", good])
        self.assertDenied(["--config", bad])

    def test_connection_override_destination_is_checked(self):
        # curl --resolve host:port:addr sends the bytes to addr while the
        # command line only ever names host. Both ends must be judged, so a
        # private or metadata destination denies even though the host is fine.
        self.assertDenied(
            ["--resolve", "example.com:443:10.0.0.1", "https://example.com"]
        )
        self.assertDenied(
            ["--resolve", "example.com:443:169.254.169.254", "https://example.com"]
        )
        # A literal address is not allowlisted, so this denies too. That is the
        # deliberate policy: an IP must be authorized explicitly, which is the
        # same human gate hunter.md applies to origin-IP scanning.
        self.assertDenied(
            ["--resolve", "example.com:443:9.9.9.9", "https://example.com"]
        )

    def test_connect_to_destination_is_checked(self):
        self.assertDenied(
            ["--connect-to", "::example.com:evil.com:443", "https://example.com"]
        )

    def test_redirect_flag_is_not_a_list_flag(self):
        # Regression: _norm_flag lowercased, so curl -L (follow redirects) was
        # indistinguishable from nuclei -l (target list) and the URL was read
        # as a filename. Short options are case-sensitive.
        self.assertAllowed(["-L", "https://example.com"])
        self.assertDenied(["-L", "https://evil.com"])
        self.assertAllowed(["--location", "https://example.com"])
        # The lowercase form is still a real list flag.
        self.assertDenied(["-l", self._write("lst.txt", ["evil.com"])])

    def test_short_option_case_is_preserved(self):
        # -p and -P differ, -t and -T differ, -H and -h differ.
        self.assertAllowed(["-sV", "-p", "80", "443", "example.com"])
        self.assertAllowed(["-P", "80", "example.com"])
        self.assertAllowed(["-T", "50", "-severity", "high", "-u", "example.com"])
        self.assertAllowed(["-H", "Cookie: a=1", "-u", "example.com"])

    def test_should_interpose(self):
        self.assertTrue(should_interpose("nmap"))
        self.assertTrue(should_interpose("sqlmap"))
        self.assertFalse(should_interpose("git"))
        self.assertFalse(should_interpose("/usr/bin/ls"))

    def test_guarded_tools_exclude_pathless_binaries(self):
        self.assertNotIn("ls", GUARDED_TOOLS)
        self.assertNotIn("bash", GUARDED_TOOLS)


class ToolGuardFuzzTest(unittest.TestCase):
    """The guard must never raise on hostile input, and must never allow
    an explicitly out-of-scope host."""

    HOSTILE = [
        [],
        ["-"],
        ["--"],
        [""],
        ["   "],
        ["-u", ""],
        ["-u", "://"],
        ["-u", "http://"],
        ["-u", "http://@"],
        ["-u", "http://:80"],
        ["-u", "..."],
        ["-u", "a..b"],
        ["-u", "-"],
        ["-u", "--"],
        ["-u", "\x00"],
        ["-u", "ex ample.com"],
        ["-u", "http://[::"],
        ["-u", "http://[::1"],
        ["-l", ""],
        ["-l", "C:\\nope\\x.txt"],
        ["-u", "x" * 5000],
        ["-" * 500 + "u", "example.com"],
        ["-u", "evil.com", "--", "example.com"],
        ["\u0000", "evil.com"],
        ["-u", "http://evil.com\\@example.com"],
        ["-u", "①evil.com"],
        ["-u", "exam\u200bple.com"],
        ["-u", "http://evil.com:99999999999"],
        ["-p", "-u", "example.com"],
        ["-u", "--", "evil.com"],
    ]

    def test_hostile_input_never_raises(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            allowlist = pathlib.Path(tmp.name) / "SCOPE_ALLOWLIST.txt"
            allowlist.write_text("example.com\n", encoding="utf-8")
            for argv in self.HOSTILE:
                try:
                    allowed, reason = guard_argv(argv, allowlist)
                except Exception as exc:  # noqa: BLE001
                    self.fail(f"guard_argv raised on {argv!r}: {exc!r}")
                self.assertIsInstance(allowed, bool)
                self.assertIsInstance(reason, str)
        finally:
            tmp.cleanup()

    def test_explicit_out_of_scope_host_is_always_denied(self):
        tmp = tempfile.TemporaryDirectory()
        try:
            allowlist = pathlib.Path(tmp.name) / "SCOPE_ALLOWLIST.txt"
            allowlist.write_text("example.com\n", encoding="utf-8")
            for argv in self.HOSTILE:
                allowed, _ = guard_argv(argv, allowlist)
                if "evil.com" in " ".join(argv):
                    self.assertFalse(allowed, f"evil.com allowed in {argv!r}")
        finally:
            tmp.cleanup()


class OracleScopeTest(unittest.TestCase):
    """Oracles issue real HTTP requests, so they must obey the same gate.

    Before this was wired, `core/oracles.py` had no caller at all and made nine
    unscoped requests with `verify=False`. Dead code that can still send traffic
    is an authorisation hole waiting to be used by accident.
    """

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.allowlist = pathlib.Path(self.tmp.name) / "SCOPE_ALLOWLIST.txt"
        self.allowlist.write_text("example.com\n", encoding="utf-8")
        import core.scope_policy as scope_policy
        import core.tool_guard as tool_guard

        self._saved = (scope_policy.DEFAULT_ALLOWLIST, tool_guard.DEFAULT_ALLOWLIST)
        scope_policy.DEFAULT_ALLOWLIST = self.allowlist
        tool_guard.DEFAULT_ALLOWLIST = self.allowlist

    def tearDown(self) -> None:
        import core.scope_policy as scope_policy
        import core.tool_guard as tool_guard

        scope_policy.DEFAULT_ALLOWLIST, tool_guard.DEFAULT_ALLOWLIST = self._saved
        self.tmp.cleanup()

    def test_oracle_refuses_out_of_scope_url(self):
        from core import oracles

        with self.assertRaises(oracles.ScopeViolation):
            oracles._require_scope("https://evil.com/x?id=1")

    def test_oracle_refuses_metadata_endpoint(self):
        from core import oracles

        with self.assertRaises(oracles.ScopeViolation):
            oracles._require_scope("http://169.254.169.254/latest/meta-data/")

    def test_oracle_permits_in_scope_url(self):
        from core import oracles

        oracles._require_scope("https://example.com/x?id=1")  # must not raise

    def test_oracle_source_has_no_disabled_tls(self):
        source = (
            pathlib.Path(__file__).resolve().parent.parent / "core" / "oracles.py"
        ).read_text(encoding="utf-8")
        code = "\n".join(
            line for line in source.splitlines() if not line.lstrip().startswith("#")
        )
        self.assertNotIn("verify=False", code)


if __name__ == "__main__":
    unittest.main(verbosity=2)
