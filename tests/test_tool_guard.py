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

    def test_proxy_flag_is_not_a_target(self):
        self.assertAllowed(["-x", "socks5://127.0.0.1:9050", "-u", "example.com"])

    # -- interposition policy ---------------------------------------------
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
