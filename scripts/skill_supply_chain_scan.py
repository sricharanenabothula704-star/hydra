"""Supply-chain scanning for skill modules.

Agent skills execute with implicit trust and minimal vetting. Analysis of
31,132 public agent skills found 26.1% contained vulnerabilities and 5.2%
showed likely malicious intent. A large curated library is therefore an
attack surface, not only an asset.

This scanner vets HYDRA's own corpus and reports what it finds. Two things
make the output usable rather than a firehose:

**Severity is tiered by whether the text is executable.** A `curl -k` inside a
markdown playbook is a documented technique; the same string inside a ``.sh``
file is a live defect. Executable files surface at ``high``/``critical``;
documentation surfaces at ``informational`` and is still reported, because a
playbook that teaches an unsafe default is still a finding.

**Findings are typed by mechanism, not by pattern shape.** Each rule names
what goes wrong, so a triage decision does not require re-reading the source.

Rules are deterministic and model-free. They are not a malware classifier and
are not presented as one: the goal is repeatable triage of one's own corpus,
so that a maintainer can review every hit rather than trust a verdict.

Usage::

    python scripts/skill_supply_chain_scan.py                 # full report
    python scripts/skill_supply_chain_scan.py --fail-on high # CI gate
    python scripts/skill_supply_chain_scan.py --json          # machine readable
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SKILLS_DIR = REPO_ROOT / "skills"

EXECUTABLE_SUFFIXES = {".py", ".sh", ".ps1", ".bat", ".rb", ".psm1"}
DOC_SUFFIXES = {".md", ".txt", ".rst", ".yaml", ".yml", ".json"}

MAX_LINE_CHARS = 400


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str  # critical | high | medium | low | informational
    title: str
    mechanism: str
    pattern: re.Pattern[str]
    executable_only: bool = False


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


RULES: tuple[Rule, ...] = (
    Rule(
        id="EXEC-BASE64-PIPE",
        severity="critical",
        title="Base64 decode piped into execution",
        mechanism="Obfuscated remote-code execution: hides payload contents from review.",
        pattern=_p(r"base64\s+(?:-d|--decode)[^|\n]*\|\s*(?:sudo\s+)?(?:ba)?sh"),
        executable_only=True,
    ),
    Rule(
        id="EXEC-CURL-PIPE-SHELL",
        severity="critical",
        title="Remote script piped directly to a shell",
        mechanism=(
            "Executes unreviewed code from the network and defeats code review; "
            "a compromised or hijacked host runs arbitrary commands."
        ),
        pattern=_p(r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh"),
        executable_only=True,
    ),
    Rule(
        id="CRED-SSH-KEY-READ",
        severity="critical",
        title="Reads private key material",
        mechanism=(
            "Access to ~/.ssh, ~/.aws, key stores or credential databases "
            "turns a testing tool into a credential-exfiltration path."
        ),
        pattern=_p(
            r"(?:~\/\.ssh|id_rsa|id_ed25519|\.aws\/credentials|"
            r"credentials\.json|\.netrc|\.docker\/config\.json|"
            r"Login\s?Data|key4\.db|logins\.json)"
        ),
        executable_only=True,
    ),
    Rule(
        id="NET-TLS-VERIFY-DISABLED",
        severity="high",
        title="TLS certificate verification disabled",
        mechanism=(
            "verify=False / InsecureSkipVerify / curl -k removes the trust "
            "anchor, so responses can be forged by an on-path attacker."
        ),
        pattern=_p(
            r"verify\s*=\s*False|InsecureSkipVerify|"
            r"CERT_NONE|curl\b[^\n]*\s-k\b|wget\b[^\n]*--no-check-certificate"
        ),
    ),
    Rule(
        id="NET-HARDENED-BYPASS",
        severity="high",
        title="Security-control hardening instructions",
        mechanism=(
            "Disabling or weakening a defensive control; legitimate only in a "
            "lab, never as a default instruction."
        ),
        pattern=_p(
            r"setenforce\s+0|iptables\s+-F|systemctl\s+stop\s+(?:firewalld|"
            r"ufw|apparmor)|defender.*(?:Disable|ExclusionPath)|"
            r"Set-MpPreference\s+-ExclusionPath|"
            r"sysctl\s+-w\s+kernel\.randomize_va_space\s*=\s*0"
        ),
        executable_only=True,
    ),
    Rule(
        id="EXEC-DESTRUCTIVE-UNGUARDED",
        severity="high",
        title="Destructive system or data command",
        mechanism=(
            "Irreversible deletion or wipe; must never be reachable without an "
            "explicit authorization gate."
        ),
        pattern=_p(
            r"\brm\s+-[rf]{1,2}\s+/|\bmkfs(?:\.\w+)?\s|"
            r"\bDROP\s+(?:DATABASE|TABLE)\b|\bTRUNCATE\s+TABLE\b|"
            r"diskpart|Remove-Item\s+.*-Recurse.*-Force.*[A-Z]:\\"
        ),
        executable_only=True,
    ),
    Rule(
        id="EXEC-SHELL-TRUE",
        severity="medium",
        title="Shell=True subprocess construction",
        mechanism=(
            "String-formatted shell invocation is the standard Python command "
            "injection surface."
        ),
        pattern=_p(r"shell\s*=\s*True"),
        executable_only=True,
    ),
    Rule(
        id="EXEC-EVAL-UNTRUSTED",
        severity="high",
        title="Dynamic evaluation of runtime-supplied code",
        mechanism=(
            "exec/eval/pickle on externally influenced input executes attacker-"
            "controlled code in-process."
        ),
        pattern=_p(r"(?<![A-Za-z0-9_])(?:eval|exec)\s*\(|pickle\.loads?\s*\("),
        executable_only=True,
    ),
    Rule(
        id="NET-SCOPE-UNBOUNDED",
        severity="medium",
        title="Network enumeration without an explicit bound",
        mechanism=(
            "Unbounded scans of a third-party host exceed authorized scope and "
            "risk availability impact."
        ),
        pattern=_p(
            r"-p\s*-|--p(?:ort)?-range\s+[\d-]*-|full\s+port\s+scan|"
            r"nmap\b[^\n]*-p\s*-|masscan\b|naabu\b"
        ),
    ),
    Rule(
        id="SEC-HARDCODED-SECRET",
        severity="critical",
        title="Secret-shaped literal",
        mechanism="Committed credentials are readable by anyone with repo access.",
        pattern=_p(
            r"(?:AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
            r"sk-(?:live|prod|test)?_?[A-Za-z0-9]{24,}|"
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----|"
            r"xox[baprs]-[A-Za-z0-9-]{12,})"
        ),
    ),
)

# Documentation placeholders that make a secret-shaped string intentional.
_PLACEHOLDER = re.compile(
    r"EXAMPLE|EXPOSED|example\.com|YOUR[_-]|<your|placeholder|X{6,}|REDACTED|"
    r"\*\*\*|\.\.\.|\[|<[A-Z_]{3,}>",
    re.IGNORECASE,
)

_RULES_BY_ID = {r.id: r for r in RULES}


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    mechanism: str
    path: str
    line_number: int
    snippet: str
    executable: bool

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    scanned_files: int = 0
    executable_files: int = 0
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[tuple[Finding, str]] = field(default_factory=list)
    skipped_large: int = 0

    def by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for f in self.findings:
            counts[f.severity] = counts.get(f.severity, 0) + 1
        return counts

    def actionable(self) -> list[Finding]:
        """Findings a maintainer must resolve before shipping."""
        return [
            f for f in self.findings if f.severity in {"critical", "high", "medium"}
        ]

    def to_dict(self) -> dict:
        return {
            "scanned_files": self.scanned_files,
            "executable_files": self.executable_files,
            "skipped_large": self.skipped_large,
            "counts_by_severity": self.by_severity(),
            "actionable": len(self.actionable()),
            "suppressed": len(self.suppressed),
            "findings": [f.to_dict() for f in self.findings],
            "suppressions": [
                {
                    "rule_id": f.rule_id,
                    "path": f.path,
                    "line_number": f.line_number,
                    "reason": reason,
                }
                for f, reason in self.suppressed
            ],
        }


# --------------------------------------------------------------------------
# Reviewed suppressions.
#
# A pattern scanner cannot distinguish a tool that *hunts* a dangerous
# construct from a tool that *is* one. A credential-recovery utility lists
# browser profile paths because those are its targets; a CI supply-chain
# scanner greps for `curl | sh` because that is the thing it detects.
#
# Suppressions are therefore explicit, per-path, and each carries a written
# reason that is reviewed when the file changes. Nothing is suppressed by
# wildcard or by rule id alone: a blanket suppression would hide the next
# real finding in the same file.
# --------------------------------------------------------------------------

SUPPRESSION_FILE = REPO_ROOT / ".skill-scan-suppressions.json"


@dataclass(frozen=True)
class Suppression:
    path: str
    rule_id: str
    reason: str


def load_suppressions(root: Path | None = None) -> tuple[Suppression, ...]:
    root = root or REPO_ROOT
    path = root / ".skill-scan-suppressions.json"
    if not path.is_file():
        return ()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ()
    out: list[Suppression] = []
    for entry in data.get("suppressions", []):
        try:
            out.append(
                Suppression(
                    path=entry["path"].replace("\\", "/"),
                    rule_id=entry["rule_id"],
                    reason=entry["reason"],
                )
            )
        except (KeyError, TypeError):
            continue
    return tuple(out)


class SuppressionSet:
    """File-scoped suppressions. Line numbers are deliberately not pinned."""

    def __init__(self, suppressions: tuple[Suppression, ...] = ()):
        self._by_path: dict[str, set[str]] = {}
        self._reasons: dict[tuple[str, str], str] = {}
        for s in suppressions:
            self._by_path.setdefault(s.path, set()).add(s.rule_id)
            self._reasons[(s.path, s.rule_id)] = s.reason

    def check(self, finding: Finding) -> str | None:
        return self._reasons.get((finding.path, finding.rule_id))

    def __len__(self) -> int:
        return len(self._reasons)


def _snippet(line: str) -> str:
    cleaned = line.strip()
    return cleaned[:MAX_LINE_CHARS]


def scan_text(
    text: str,
    path: str,
    executable: bool,
    suppressions: "SuppressionSet | None" = None,
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    """Return (findings, suppressed). A suppressed finding is never discarded."""
    findings: list[Finding] = []
    suppressed: list[tuple[Finding, str]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        if len(line) > 4000:
            continue
        for rule in RULES:
            if rule.executable_only and not executable:
                continue
            if not rule.pattern.search(line):
                continue
            if rule.id == "SEC-HARDCODED-SECRET" and _PLACEHOLDER.search(line):
                continue
            severity = rule.severity
            if not executable:
                # Same pattern, different blast radius: shown, not executed.
                severity = "informational"
            finding = Finding(
                rule_id=rule.id,
                severity=severity,
                title=rule.title,
                mechanism=rule.mechanism,
                path=path,
                line_number=lineno,
                snippet=_snippet(line),
                executable=executable,
            )
            reason = suppressions.check(finding) if suppressions else None
            if reason is not None:
                suppressed.append((finding, reason))
            else:
                findings.append(finding)
    return findings, suppressed


def scan_file(
    path: Path, root: Path, suppressions: "SuppressionSet | None" = None
) -> tuple[list[Finding], list[tuple[Finding, str]]]:
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], []
    suffix = path.suffix.lower()
    return scan_text(
        text,
        str(path.relative_to(root)).replace("\\", "/"),
        suffix in EXECUTABLE_SUFFIXES,
        suppressions,
    )


def scan_corpus(root: Path | None = None) -> ScanReport:
    root = root or REPO_ROOT
    skills = root / "skills"
    report = ScanReport()
    suppressions = SuppressionSet(load_suppressions(root))

    if not skills.is_dir():
        return report

    for path in sorted(skills.rglob("*")):
        if not path.is_file():
            continue
        suffix = path.suffix.lower()
        if suffix not in EXECUTABLE_SUFFIXES | DOC_SUFFIXES:
            continue
        try:
            if path.stat().st_size > 4 * 1024 * 1024:
                report.skipped_large += 1
                continue
        except OSError:
            continue
        report.scanned_files += 1
        if suffix in EXECUTABLE_SUFFIXES:
            report.executable_files += 1
        found, hidden = scan_file(path, root, suppressions)
        report.findings.extend(found)
        report.suppressed.extend(hidden)

    return report


def render(report: ScanReport) -> str:
    counts = report.by_severity()
    actionable = report.actionable()
    lines = [
        "HYDRA skill supply-chain scan",
        "=" * 72,
        f"files scanned     : {report.scanned_files}",
        f"  executable      : {report.executable_files}",
        f"  documentation   : {report.scanned_files - report.executable_files}",
        f"skipped (>4MB)    : {report.skipped_large}",
        "",
        "findings by severity: "
        + (", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "none"),
        f"actionable        : {len(actionable)}",
        "=" * 72,
        "",
    ]

    if not actionable:
        lines.append(
            "No actionable findings. Documentation matches are listed below for "
            "review and are informational by design."
        )
    else:
        lines.append("ACTIONABLE FINDINGS (executable files, resolve before release)")
        for f in sorted(actionable, key=lambda x: (x.severity, x.path)):
            lines.append(
                f"  [{f.severity.upper()}] {f.rule_id}  {f.path}:{f.line_number}"
            )
            lines.append(f"      {f.title}")
            lines.append(f"      mechanism: {f.mechanism}")
            lines.append(f"      snippet:   {f.snippet}")
        lines.append("")

    informational = [f for f in report.findings if f.severity == "informational"]
    if informational:
        lines.append(f"DOCUMENTATION MATCHES ({len(informational)}, informational)")
        grouped: dict[str, list[Finding]] = {}
        for f in informational:
            grouped.setdefault(f.rule_id, []).append(f)
        for rule_id in sorted(grouped):
            items = grouped[rule_id]
            rule = _RULES_BY_ID[rule_id]
            lines.append(f"  {rule_id:<28} {len(items):>4}  {rule.title}")
        lines.append("")
        lines.append(
            "These are techniques shown inside playbooks, not live code. They are "
            "reported so a maintainer can confirm each is intentional."
        )

    lines.append("")
    lines.append(
        "This is a deterministic pattern scan, not a malware classifier. It "
        "supports triage and does not replace review."
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan HYDRA skills for supply-chain risk."
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "never"],
        default="never",
        help="exit non-zero when a finding at or above this severity exists",
    )
    parser.add_argument("--root", default=None, help="repository root override")
    args = parser.parse_args(argv)

    root = Path(args.root) if args.root else REPO_ROOT
    report = scan_corpus(root)

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print(render(report))

    if args.fail_on == "never":
        return 0
    threshold = {"critical": 3, "high": 2, "medium": 1, "low": 0}[args.fail_on]
    rank = {"critical": 3, "high": 2, "medium": 1, "low": 0, "informational": -1}
    blocking = [f for f in report.findings if rank.get(f.severity, -1) >= threshold]
    if blocking:
        print(f"\nFAILED: {len(blocking)} finding(s) at or above '{args.fail_on}'.")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
