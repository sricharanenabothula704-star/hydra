#!/usr/bin/env python3
"""Argv-level scope enforcement for external recon/fuzzing tools.

The scope gate in :mod:`core.scope_policy` is a hostname allowlist. Historically
it was only consulted by the CLI and the loop runner, which meant the gate was a
fence *around* the CLI rather than around the work: once an agent session or a
helper script invoked ``sqlmap`` or ``nuclei`` directly, authorization was down
to the model obeying a prompt instruction. An audit found 21 network-touching
helper scripts that never consulted the gate at all.

This module closes that gap by making the guard part of the tool invocation
instead of the caller. The shims in ``bin/guard-bin/`` sit earlier on ``PATH``
than the real binaries and call :func:`guard_argv` on the full argument vector
before exec-ing the genuine tool. Enforcement therefore survives:

* a helper script that forgets to check scope,
* an agent that calls a tool directly instead of going through the CLI,
* a new script added later that nobody audited.

Design rules:

* **Fail closed for identified targets.** A host outside the allowlist, or a
  non-routable literal, does not run.
* **All targets are checked**, not just the first. One out-of-scope host in a
  mixed command line is a denial.
* **Lists are followed.** ``-l hosts.txt`` hides targets in a file, the obvious
  way to defeat an argv scan, so list arguments are read and every entry
  checked. An unreadable list is a denial, not a skip.
* **Deterministic and offline.** Classification is string handling plus literal
  address checks; no DNS, so the guard behaves identically on a laptop with no
  network.

Known limitation: this is defence in depth, not a sandbox. It reasons about
argument vectors, and an adversary who controls the command line can obscure
targets from any argv parser. The control that actually survives a compromised
agent is an outbound proxy that only permits authorized destinations; see
``docs/ENFORCEMENT.md``.

Usage::

    python -m core.tool_guard nmap -sV example.com     # check, then exec
    python -m core.tool_guard --check sqlmap -u ...    # check only, never exec
    python -m core.tool_guard nmap --print-targets -l hosts.txt
"""

from __future__ import annotations

import ipaddress
import os
import pathlib
import re
import sys
from typing import Sequence

from core.scope_policy import DEFAULT_ALLOWLIST, normalize_host, scope_decision

#: Tools this guard interposes on. Anything else is passed through untouched.
GUARDED_TOOLS = frozenset(
    {
        "arjun",
        "commix",
        "curl",
        "dalfox",
        "dirsearch",
        "ffuf",
        "feroxbuster",
        "gobuster",
        "httpx",
        "katana",
        "masscan",
        "naabu",
        "nikto",
        "nmap",
        "nuclei",
        "sqlmap",
        "subfinder",
        "wget",
        "whatweb",
    }
)

#: Extensions treated as target lists when passed positionally.
LIST_SUFFIXES = (".txt", ".lst", ".list", ".hosts", ".csv")

#: Flags whose value IS a target. Keys are normalised (leading dashes stripped),
#: so ``-u``, ``--url``, ``-d`` and ``--domain`` all match. These must never have
#: their values skipped: ``-u`` is the primary target flag for sqlmap, ffuf,
#: nuclei and httpx, and treating it as a username flag drops the only host on
#: the command line.
TARGET_VALUE_FLAGS = frozenset(
    {
        "u",
        "url",
        "urls",
        "host",
        "hostname",
        "d",
        "domain",
        "target",
        "base",
        "baseurl",
        "origin",
        "endpoint",
        "root",
        "web",
    }
)

#: Flags whose value is a file of targets rather than a target itself.
LIST_FLAGS = frozenset(
    {
        "l",
        "list",
        "list-file",
        "targets",
        "target-file",
        "domain-list",
    }
)

#: Flags whose value is a *document* that carries targets in free-form text:
#: an HTTP request file (sqlmap ``-r``), or a tool config/profile that embeds a
#: target list. These are the documented way to reach a host without it ever
#: appearing as a target argument, so the file is read and every host in it is
#: checked.
DOCUMENT_FILE_FLAGS = frozenset(
    {
        "r",
        "request",
        "request-file",
        "c",
        "config",
        "conf",
        "profile",
    }
)

#: Connection-override flags that name one host but send the traffic somewhere
#: else. ``curl --resolve host:port:addr`` sends to ``addr`` while the command
#: line only ever mentions ``host``; checking the host alone misses the
#: destination entirely. Both ends are therefore extracted.
RESOLVE_FLAGS = frozenset({"resolve", "resolve6", "connect-to"})

#: Transport flags. Traffic is sent to these hosts rather than to the target,
#: so they are checked as targets in their own right. An external proxy in a
#: bug bounty command line is usually either unauthorised infrastructure or a
#: way to move traffic somewhere the program never agreed to.
PROXY_FLAGS = frozenset({"proxy", "x", "proxysocks5", "socks5-hostname"})

#: Flags whose value must never be mistaken for a target. Templates, wordlists,
#: output paths, ports, rates, header strings and severity keywords all sit next
#: to target flags and are the main source of false denials.
NON_TARGET_VALUE_FLAGS = frozenset(
    {
        "p",
        "port",
        "ports",
        "rate",
        "rl",
        "timeout",
        "retries",
        "max-rate",
        "concurrency",
        "threads",
        "t",
        "templates",
        "template",
        "T",
        "severity",
        "severities",
        "o",
        "output",
        "w",
        "wordlist",
        "wordlists",
        "b",
        "data",
        "data-raw",
        "H",
        "header",
        "headers",
        "s",
        "sni",
        "e",
        "engine",
        "payload",
        "user-agent",
        "U",
        "user",
        "username",
        "password",
        "method",
        "X",
        "resolver",
        "max-hostgroup",
        "g",
        "pps",
        "top-ports",
        "top-port",
        "exclude",
        "user-agents",
        "matcher",
        "matchers",
        "tags",
        "exclude-tags",
        "stats",
    }
)

#: Single-label tokens that are local names rather than routable target hosts.
LOCAL_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})

#: Vocabulary that is clearly not a hostname, to avoid denying on prose.
NOT_HOST_WORDS = frozenset(
    {
        "true",
        "false",
        "none",
        "null",
        "all",
        "any",
        "yes",
        "no",
        "on",
        "off",
        "get",
        "post",
        "put",
        "patch",
        "delete",
        "head",
        "options",
        "json",
        "xml",
        "html",
        "text",
        "plain",
        "info",
        "critical",
        "high",
        "medium",
        "low",
        "unknown",
        "fast",
        "slow",
        "silent",
        "verbose",
        "quiet",
        "debug",
    }
)

_HOSTLIKE = re.compile(
    r"""^
    (?:
        [a-z][a-z0-9+.\-]*://                       # scheme
        (?P<userinfo>[^\s@/]*@)?                     # optional userinfo
        (?P<urlhost>[^\s:/?\#\[\]]+                  # reg-name
                    | \[[0-9A-Fa-f:.]+\]             # IPv6 literal in brackets
        )
        [^/?\#]*                                    # port, path, query: ignored
      |
        (?P<bare>[A-Za-z0-9_.*\-\[\]:%/]+)$          # bare host, IP, IPv6, CIDR
    )
    """,
    re.VERBOSE | re.IGNORECASE,
)

_BARE_IPV6 = re.compile(r"^\[[0-9A-Fa-f:.]+\](?:/\d{1,3})?$")


def _norm_flag(token: str) -> str:
    """Normalise a flag token to a lookup key.

    Case is preserved for single-dash short options and folded for long
    options. This distinction is load-bearing: curl's ``-L`` (follow
    redirects) shares a letter with nuclei's ``-l`` (target list), nmap's
    ``-p`` (ports) shares with ``-P``, and ``-H``/``-h`` and ``-t``/``-T``
    differ the same way. Lowercasing everything made ``curl -L https://host``
    parse as "read this target list, https://host", which failed closed for
    the wrong reason and made a redirect flag look like a list argument.

    Unknown single-dash options deliberately fall through rather than being
    treated as "skip the next token", so their value is parsed as a candidate
    and checked. That is the safe direction for a control that fails closed.
    """
    body = token.lstrip("-")
    return body.lower() if token.startswith("--") else body


def _is_flag(token: str) -> bool:
    return token.startswith("-") and token not in {"-", "--"}


def _candidate_from_token(token: str) -> str | None:
    """Reduce one token to a bare host, or ``None`` if it is not a target.

    Conservative by design. Returning ``None`` too often weakens the guard;
    treating a template path or a severity keyword as a host denies a
    legitimate run, which is worse than missing a target because the
    allowlist check on the *other* targets still applies.
    """
    token = token.strip().strip("'\"").rstrip(",;")
    if not token or _is_flag(token):
        return None

    # CIDR and bracketed IPv6 are address literals, so judge them before the
    # filesystem-shape rejection below would discard them for containing "/".
    address_shape = bool(
        re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}", token)
        or _BARE_IPV6.match(token)
        or re.fullmatch(r"[0-9A-Fa-f]*:[0-9A-Fa-f:.]+(?:/\d{1,3})?", token)
    )

    # Reject obvious filesystem shapes before anything else.
    if not address_shape:
        if token.startswith(("/", "./", "../", "~/")) or token.startswith("\\\\"):
            return None
        if ("/" in token or "\\" in token) and "://" not in token:
            return None
        if "=" in token and "://" not in token and "/" not in token:
            return None

    match = _HOSTLIKE.match(token)
    if not match:
        return None

    if match.group("urlhost") is not None:
        # Userinfo in a scan target is never legitimate. It exists either for
        # credential tricks or to create a URL-parser differential:
        # "http://evil.com\@example.com" is read as host "example.com" by a
        # strict parser and as host "evil.com" by a lenient one. Since the
        # guard cannot know which parser the downstream tool uses, such a token
        # yields no target and therefore fails closed.
        if match.group("userinfo") is not None:
            return None
        raw = match.group("urlhost")
    else:
        raw = match.group("bare")

    # Strip a trailing port, then brackets, then any CIDR prefix. Order matters:
    # "[::1]:8080" must lose the port before the bracket, and "10.0.0.0/24" must
    # keep its network address rather than being read as a path.
    raw = raw.strip()
    if raw.startswith("["):
        close = raw.find("]")
        if close == -1:
            return None
        host = raw[: close + 1]
    elif raw.count(":") == 1:
        host = raw.split(":", 1)[0]
    else:
        host = raw

    host = host.rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if not host:
        return None

    # A literal address is always a candidate; let the address checks judge it.
    probe = host.strip("[]").split("%", 1)[0]
    try:
        ipaddress.ip_address(probe)
        return host
    except ValueError:
        pass
    if "/" in probe:
        try:
            ipaddress.ip_network(probe, strict=False)
            return host
        except ValueError:
            return None

    if host.lower() in LOCAL_NAMES:
        return host

    # Otherwise it must look like a real DNS name: at least one dot, and only
    # hostname-legal characters. This is what excludes ``high``, ``templates``
    # and ``json``, which arrive as values or stray positionals.
    if host.lower() in NOT_HOST_WORDS:
        return None
    if "." not in host:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.\-]+", host):
        return None
    if host.startswith(".") or ".." in host:
        return None
    # Require a plausible TLD so that ``file.txt``-like tokens and stray paths
    # do not become targets.
    tld = host.rsplit(".", 1)[-1].lower()
    if not (2 <= len(tld) <= 24 and tld.isalpha()):
        return None
    return host


def _read_list_file(path: pathlib.Path, max_lines: int = 20_000) -> list[str]:
    """Best-effort read of a target list. Unreadable files yield nothing."""
    try:
        if path.stat().st_size > 4 * 1024 * 1024:
            return []
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return [ln.strip() for ln in raw.splitlines()[:max_lines] if ln.strip()]


def _targets_from_list(path_text: str) -> tuple[list[str], bool]:
    """Return ``(targets, readable)`` for a list file.

    ``readable`` is False when the path looks like a list but yielded nothing,
    which the caller treats as a denial so the tool never runs blind.
    """
    targets: list[str] = []
    entries = _read_list_file(pathlib.Path(path_text))
    for entry in entries:
        first = entry.split()[0] if entry.split() else entry
        host = _candidate_from_token(first)
        if host:
            targets.append(host)
    return targets, bool(entries)


def _targets_from_document(path_text: str) -> tuple[list[str], bool]:
    """Extract hosts from a free-form document that carries targets.

    Covers the documented ways to reach a host without naming it as a target
    argument:

    * an HTTP request file (``sqlmap -r req.txt``) names the host in a
      ``Host:`` header or an absolute request URI, never in a bare argument;
    * a tool config or profile (``nuclei -c conf.yaml``) embeds a target list
      in YAML, TOML or JSON.

    Scans every whitespace-separated token in the file rather than trying to
    parse the format, because a format-specific parser would be one more thing
    to get wrong in a security control. A document that yields no host is
    reported as unreadable, so it denies rather than passing through.
    """
    path = pathlib.Path(path_text)
    entries = _read_list_file(path)
    targets: list[str] = []
    for entry in entries:
        for token in entry.replace(",", " ").split():
            bare = token.strip("'\"{}[]()")
            if not bare or bare.startswith("-"):
                continue
            # "Host:example.com" and "Host: example.com" both reach here.
            if ":" in bare and "://" not in bare:
                head, _, tail = bare.partition(":")
                if head.strip().lower() == "host" and tail.strip():
                    bare = tail.strip()
            host = _candidate_from_token(bare)
            if host:
                targets.append(host)
    return targets, bool(entries)


def _targets_from_resolve(value: str) -> list[str]:
    """Extract both ends of a connection override.

    ``curl --resolve example.com:443:9.9.9.9`` names one host and sends the
    bytes to another. Checking only the named host misses the actual
    destination, so both the reg-name and each supplied address are returned.
    """
    found: list[str] = []
    for entry in value.split(","):
        parts = [p.strip() for p in entry.split(":") if p.strip()]
        if not parts:
            continue
        host = _candidate_from_token(parts[0])
        if host:
            found.append(host)
        for part in parts[1:]:
            addr = _candidate_from_token(part)
            if addr:
                found.append(addr)
    return found


def extract_targets(argv: Sequence[str]) -> tuple[list[str], list[str]]:
    """Return ``(targets, unreadable_lists)`` for a tool argument vector."""
    targets: list[str] = []
    unreadable: list[str] = []
    tokens = list(argv)
    i = 0

    while i < len(tokens):
        token = tokens[i]

        if _is_flag(token):
            name, sep, inline = token.partition("=")
            norm = _norm_flag(name)

            if norm in LIST_FLAGS:
                path_text = (
                    inline if sep else (tokens[i + 1] if i + 1 < len(tokens) else "")
                )
                if path_text:
                    found, readable = _targets_from_document(path_text)
                    targets.extend(found)
                    if not readable:
                        unreadable.append(path_text)
                i += 1 if sep else 2
                continue

            if norm in DOCUMENT_FILE_FLAGS:
                path_text = (
                    inline if sep else (tokens[i + 1] if i + 1 < len(tokens) else "")
                )
                if path_text:
                    found, readable = _targets_from_document(path_text)
                    targets.extend(found)
                    if not readable:
                        unreadable.append(path_text)
                i += 1 if sep else 2
                continue

            if norm in RESOLVE_FLAGS or norm in PROXY_FLAGS:
                value = (
                    inline if sep else (tokens[i + 1] if i + 1 < len(tokens) else "")
                )
                if value:
                    if norm in RESOLVE_FLAGS:
                        targets.extend(_targets_from_resolve(value))
                    else:
                        host = _candidate_from_token(value)
                        if host:
                            targets.append(host)
                i += 1 if sep else 2
                continue

            if norm in TARGET_VALUE_FLAGS:
                value = (
                    inline if sep else (tokens[i + 1] if i + 1 < len(tokens) else "")
                )
                host = _candidate_from_token(value) if value else None
                if host:
                    targets.append(host)
                i += 1 if sep else 2
                continue

            if norm in NON_TARGET_VALUE_FLAGS:
                i += 1 if sep else 2
                continue

            i += 1
            continue

        # Positional token.
        if token.lower().endswith(LIST_SUFFIXES):
            found, readable = _targets_from_document(token)
            targets.extend(found)
            if not readable:
                unreadable.append(token)
            i += 1
            continue

        host = _candidate_from_token(token)
        if host:
            targets.append(host)
        i += 1

    seen: set[str] = set()
    unique = [t for t in targets if not (t in seen or seen.add(t))]
    return unique, unreadable


def _literal_address_verdict(host: str) -> str | None:
    """Deny loopback, link-local, private, reserved and metadata literals.

    Pure string handling on the literal -- no DNS -- so this is deterministic
    and works offline. ``169.254.169.254`` is the cloud instance metadata
    endpoint and is the most valuable single target for SSRF from a test rig.
    Authorized internal engagements opt out with ``HYDRA_ALLOW_PRIVATE=1``.
    """
    candidate = host
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    if "%" in candidate:  # IPv6 zone id
        candidate = candidate.split("%", 1)[0]

    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError:
        # CIDR: judge the network address.
        if "/" in candidate:
            try:
                net = ipaddress.ip_network(candidate, strict=False)
            except ValueError:
                return None
            ip = net.network_address
            candidate = str(ip)
        else:
            return None

    if str(ip) == "169.254.169.254":
        return f"{host} is the cloud instance metadata endpoint"
    if ip.is_loopback:
        return f"{host} is a loopback address"
    if ip.is_link_local:
        return f"{host} is a link-local address"
    if ip.is_private:
        return f"{host} is a private address (set HYDRA_ALLOW_PRIVATE=1 to allow)"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return f"{host} is reserved/multicast/unspecified"
    return None


#: Invocations that are informational by definition and name no target. Only
#: these are permitted to resolve zero targets; every other zero-target
#: invocation of a guarded tool is a denial. Keys are lowercase because flag
#: names are normalised with ``str.lower()``.
INFORMATIONAL_FLAGS = frozenset(
    {
        "version",
        "V",
        "v",
        "h",
        "help",
        "usage",
        "license",
    }
)


def _is_informational(argv: Sequence[str]) -> bool:
    """True when *every* token is an informational flag.

    Deliberately strict: a bare ``--version`` or ``--help`` is informational,
    but ``--version -u example.com`` is not. Requiring the whole vector to be
    informational prevents a real invocation from smuggling past the gate by
    carrying a help flag alongside a target.
    """
    tokens = [t for t in argv if t and not t.isspace()]
    if not tokens:
        return False
    return all(
        _is_flag(token) and _norm_flag(token.partition("=")[0]) in INFORMATIONAL_FLAGS
        for token in tokens
    )


def guard_argv(
    argv: Sequence[str],
    allowlist_path: pathlib.Path | None = None,
) -> tuple[bool, str]:
    """Return ``(allowed, reason)`` for a tool invocation.

    Fails closed. Denies when any identified target is outside the allowlist,
    when a target is a non-routable literal, when a target list was unreadable,
    and -- critically -- when **no target could be identified at all**. The last
    case is the one that matters: an argv parser that cannot recognise a target
    must not become a bypass, so an unrecognised invocation of a network tool is
    a denial rather than a silent pass.

    The only exemption is an explicitly informational invocation (``--version``,
    ``--help``), which names no target by definition.

    Address literals are additionally governed by the hostname allowlist: because
    the allowlist is hostname-based, an IP or CIDR that is not listed explicitly
    is denied whether or not it is publicly routable. That denies mass-scan
    ranges such as ``8.8.8.0/24`` without needing a special case.
    """
    allowlist = allowlist_path or DEFAULT_ALLOWLIST
    targets, unreadable = extract_targets(argv)

    for path_text in unreadable:
        return False, (
            f"target list {path_text!r} is unreadable or contained no recognised "
            f"hosts; refusing to run blind"
        )

    if not targets:
        if _is_informational(argv):
            return (
                True,
                "informational invocation (--version/--help); no target required",
            )
        return False, (
            "no target could be identified in this invocation, so its scope cannot "
            "be verified; refusing to run an unscoped network command. Pass an "
            "explicit target, or use --check with a supported flag form if you "
            "believe this is a false negative"
        )

    for host in targets:
        denied = _literal_address_verdict(host)
        if denied:
            return False, f"DENY {host}: {denied}"
        try:
            normalize_host(host)
        except ValueError as exc:
            return False, f"DENY {host}: unparseable target ({exc})"
        allowed, reason = scope_decision(host, allowlist)
        if not allowed:
            return False, f"DENY {host}: {reason}"

    return True, f"all {len(targets)} target(s) in scope: {', '.join(targets[:5])}"


def should_interpose(tool: str) -> bool:
    """Whether PATH shimming is appropriate for this tool name."""
    if os.environ.get("HYDRA_TOOL_GUARD", "1") == "0":
        return False
    return pathlib.Path(tool).name.lower() in GUARDED_TOOLS


def _resolve_real_binary(tool: str) -> str | None:
    """Find the genuine binary, ignoring this package's shim directory."""
    from shutil import which

    shim_dir = str(
        (pathlib.Path(__file__).resolve().parent.parent / "bin" / "guard-bin").resolve()
    )
    parts = [
        p
        for p in os.environ.get("PATH", "").split(os.pathsep)
        if p and os.path.normcase(os.path.abspath(p)) != os.path.normcase(shim_dir)
    ]
    return which(tool, path=os.pathsep.join(parts))


def main(argv: Sequence[str] | None = None) -> int:
    import argparse
    import subprocess

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("tool", help="tool being invoked (used for PATH resolution)")
    parser.add_argument(
        "--check", action="store_true", help="evaluate scope and exit without executing"
    )
    parser.add_argument("--allowlist", type=pathlib.Path, default=None)
    parser.add_argument("--print-targets", action="store_true")
    parser.add_argument("args", nargs=argparse.REMAINDER)
    ns = parser.parse_args(argv)

    tool_args = ns.args
    if tool_args and tool_args[0] == "--":
        tool_args = tool_args[1:]

    if ns.print_targets:
        targets, unreadable = extract_targets(tool_args)
        for host in targets:
            print(host)
        for path_text in unreadable:
            print(f"<unreadable-list:{path_text}>", file=sys.stderr)
        return 0

    allowed, reason = guard_argv(tool_args, ns.allowlist)

    log = os.environ.get("HYDRA_GUARD_LOG")
    if log:
        try:
            with open(log, "a", encoding="utf-8") as handle:
                handle.write(f"{ns.tool}\t{'ALLOW' if allowed else 'DENY'}\t{reason}\n")
        except OSError:
            pass

    print(f"[scope] {'ALLOW' if allowed else 'DENY'}: {reason}", file=sys.stderr)
    if not allowed:
        print(
            "[scope] Blocked. If this target IS in an active program's scope, add "
            "its domain to SCOPE_ALLOWLIST.txt first.",
            file=sys.stderr,
        )
        return 3

    if ns.check:
        return 0

    resolved = _resolve_real_binary(ns.tool)
    if resolved is None:
        print(f"[scope] cannot resolve real binary for {ns.tool!r}", file=sys.stderr)
        return 127
    try:
        return subprocess.call([resolved, *tool_args])
    except OSError as exc:
        print(f"[scope] failed to execute {resolved}: {exc}", file=sys.stderr)
        return 127


if __name__ == "__main__":
    sys.exit(main())
