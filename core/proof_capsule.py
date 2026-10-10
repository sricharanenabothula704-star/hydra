"""
HYDRA Proof Capsule — Replay-able exploit format
Portable JSON that contains everything needed to reproduce a finding.
Compatible with pentest-ai's proof capsule format.
"""
import json
import time
from typing import Optional


class ProofCapsule:
    """A self-contained, replay-able proof of a vulnerability."""

    def __init__(self, vuln_class: str, endpoint: str, method: str = "GET"):
        self.vuln_class = vuln_class
        self.endpoint = endpoint
        self.method = method.upper()
        self.payload = ""
        self.headers = {}
        self.body = ""
        self.expected_behavior = ""
        self.actual_behavior = ""
        self.evidence = []
        self.curl_command = ""
        self.python_code = ""
        self.severity = "medium"
        self.cvss = 0.0
        self.cwe = ""
        self.verified = False
        self.oracle_name = ""
        self.created_at = time.time()

    def set_request(self, payload: str = "", headers: dict = None,
                    body: str = ""):
        """Set the attack request details."""
        self.payload = payload
        self.headers = headers or {}
        self.body = body

    def set_response(self, expected: str, actual: str):
        """Set expected vs actual behavior."""
        self.expected_behavior = expected
        self.actual_behavior = actual

    def add_evidence(self, evidence_type: str, content: str):
        """Add evidence (raw request, raw response, screenshot, etc.)."""
        self.evidence.append({
            "type": evidence_type,
            "content": content,
            "timestamp": time.time(),
        })

    def generate_curl(self, target_url: str):
        """Generate curl command to reproduce."""
        url = f"{target_url}{self.endpoint}"
        if self.payload:
            url += self.payload

        parts = [f"curl -X {self.method}"]
        for k, v in self.headers.items():
            parts.append(f"-H '{k}: {v}'")
        if self.body:
            parts.append(f"-d '{self.body}'")
        parts.append(f"'{url}'")
        self.curl_command = " \\\n  ".join(parts)

    def generate_python(self, target_url: str):
        """Generate Python code to reproduce."""
        url = f"{target_url}{self.endpoint}"
        lines = [
            "import requests",
            "",
            f"url = '{url}'",
        ]
        if self.payload:
            lines.append(f"url += '{self.payload}'")
        if self.headers:
            lines.append(f"headers = {json.dumps(self.headers, indent=2)}")
        else:
            lines.append("headers = {}")
        if self.body:
            lines.append(f"data = '{self.body}'")
            lines.append(f"resp = requests.{self.method.lower()}(url, headers=headers, data=data, verify=False)")
        else:
            lines.append(f"resp = requests.{self.method.lower()}(url, headers=headers, verify=False)")
        lines.extend([
            "",
            "print(f'Status: {resp.status_code}')",
            "print(f'Response: {resp.text[:500]}')",
        ])
        self.python_code = "\n".join(lines)

    def to_dict(self) -> dict:
        """Serialize to dict."""
        return {
            "vuln_class": self.vuln_class,
            "endpoint": self.endpoint,
            "method": self.method,
            "payload": self.payload,
            "headers": self.headers,
            "body": self.body,
            "expected_behavior": self.expected_behavior,
            "actual_behavior": self.actual_behavior,
            "evidence": self.evidence,
            "curl_command": self.curl_command,
            "python_code": self.python_code,
            "severity": self.severity,
            "cvss": self.cvss,
            "cwe": self.cwe,
            "verified": self.verified,
            "oracle_name": self.oracle_name,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ProofCapsule":
        """Deserialize from dict."""
        cap = cls(
            vuln_class=data.get("vuln_class", ""),
            endpoint=data.get("endpoint", ""),
            method=data.get("method", "GET"),
        )
        cap.payload = data.get("payload", "")
        cap.headers = data.get("headers", {})
        cap.body = data.get("body", "")
        cap.expected_behavior = data.get("expected_behavior", "")
        cap.actual_behavior = data.get("actual_behavior", "")
        cap.evidence = data.get("evidence", [])
        cap.curl_command = data.get("curl_command", "")
        cap.python_code = data.get("python_code", "")
        cap.severity = data.get("severity", "medium")
        cap.cvss = data.get("cvss", 0.0)
        cap.cwe = data.get("cwe", "")
        cap.verified = data.get("verified", False)
        cap.oracle_name = data.get("oracle_name", "")
        cap.created_at = data.get("created_at", time.time())
        return cap

    def render(self) -> str:
        """Render proof capsule as human-readable text."""
        lines = [
            f"{'='*60}",
            f"PROOF CAPSULE: {self.vuln_class}",
            f"{'='*60}",
            f"Endpoint: {self.method} {self.endpoint}",
            f"Severity: {self.severity.upper()} (CVSS: {self.cvss})",
            f"Verified: {'YES' if self.verified else 'NO'}",
            f"Oracle: {self.oracle_name}",
            "",
        ]

        if self.payload:
            lines.extend(["Payload:", self.payload, ""])

        if self.expected_behavior:
            lines.extend([
                "Expected Behavior:",
                self.expected_behavior,
                "",
                "Actual Behavior:",
                self.actual_behavior,
                "",
            ])

        if self.curl_command:
            lines.extend(["Curl Command:", self.curl_command, ""])

        if self.python_code:
            lines.extend(["Python Code:", self.python_code, ""])

        if self.evidence:
            lines.append("Evidence:")
            for ev in self.evidence:
                lines.append(f"  [{ev['type']}] {ev['content'][:200]}")

        lines.append(f"{'='*60}")
        return "\n".join(lines)


def create_capsule(finding: dict, target_url: str, response_body: str = "") -> ProofCapsule:
    """Create a proof capsule from a finding dict."""
    cap = ProofCapsule(
        vuln_class=finding.get("vuln_class", "Unknown"),
        endpoint=finding.get("endpoint", ""),
        method=finding.get("method", "GET"),
    )
    cap.severity = finding.get("severity", "medium")
    cap.cvss = finding.get("cvss", 0.0)
    cap.cwe = finding.get("cwe", "")
    cap.payload = finding.get("payload", "")
    cap.headers = finding.get("headers", {})
    cap.verified = finding.get("status") == "verified"
    cap.oracle_name = finding.get("oracle_name", "")

    if response_body:
        cap.actual_behavior = response_body[:500]
        cap.add_evidence("response", response_body)

    cap.generate_curl(target_url)
    cap.generate_python(target_url)
    return cap
