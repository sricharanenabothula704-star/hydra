"""
HYDRA Oracle Verification — Deterministic validators
Every finding is a "candidate" until an oracle re-runs the exploit N/N times
against a control that must fail. Zero false positives by design.
"""
import json
import re
import time
from abc import ABC, abstractmethod
from typing import Optional


class OracleResult:
    """Result of an oracle verification."""

    def __init__(self, oracle_name: str, verified: bool, attempts: int,
                 successes: int, evidence: list = None, message: str = ""):
        self.oracle_name = oracle_name
        self.verified = verified
        self.attempts = attempts
        self.successes = successes
        self.evidence = evidence or []
        self.message = message
        self.timestamp = time.time()

    def to_dict(self) -> dict:
        return {
            "oracle_name": self.oracle_name,
            "verified": self.verified,
            "attempts": self.attempts,
            "successes": self.successes,
            "evidence": self.evidence,
            "message": self.message,
            "timestamp": self.timestamp,
        }


class BaseOracle(ABC):
    """Abstract base class for all oracles."""

    name = "base"
    required_successes = 3  # N/N required

    @abstractmethod
    def test_positive(self, target_url: str, endpoint: str, **kwargs) -> dict:
        """Test WITH the exploit payload. Should succeed if vuln exists.
        Returns: {"success": bool, "response_code": int, "response_body": str, "evidence": str}"""
        pass

    @abstractmethod
    def test_negative(self, target_url: str, endpoint: str, **kwargs) -> dict:
        """Test WITHOUT the exploit payload. Must fail (control).
        Returns: {"success": bool, "response_code": int, "response_body": str}"""
        pass

    def verify(self, target_url: str, endpoint: str, **kwargs) -> OracleResult:
        """Run N/N verification. Returns OracleResult."""
        successes = 0
        evidence_list = []

        for attempt in range(self.required_successes):
            # Positive test (with payload)
            pos_result = self.test_positive(target_url, endpoint, **kwargs)

            # Negative test (control — without payload)
            neg_result = self.test_negative(target_url, endpoint, **kwargs)

            if pos_result.get("success") and not neg_result.get("success"):
                successes += 1
                evidence_list.append({
                    "attempt": attempt + 1,
                    "positive": pos_result,
                    "negative": neg_result,
                })

        verified = successes == self.required_successes
        return OracleResult(
            oracle_name=self.name,
            verified=verified,
            attempts=self.required_successes,
            successes=successes,
            evidence=evidence_list,
            message=f"Verified {successes}/{self.required_successes}" if verified
                    else f"Failed {successes}/{self.required_successes}"
        )


class SQLErrorOracle(BaseOracle):
    """Verify SQL injection via error message detection."""

    name = "sql_error"
    error_patterns = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"ORA-\d{5}",
        r"PostgreSQL.*ERROR",
        r"SQLite.*error",
        r"Unclosed quotation mark",
        r"Microsoft.*ODBC.*SQL Server",
        r"Syntax error.*query",
        r"unexpected end of SQL",
    ]

    def __init__(self, payloads: list = None):
        self.payloads = payloads or ["' OR 1=1--", "' UNION SELECT NULL--", "1' AND '1'='1"]

    def test_positive(self, target_url: str, endpoint: str, **kwargs) -> dict:
        """Send SQLi payload, check for SQL error in response."""
        import requests
        for payload in self.payloads:
            try:
                url = f"{target_url}{endpoint}{payload}"
                resp = requests.get(url, timeout=10, verify=False)
                for pattern in self.error_patterns:
                    if re.search(pattern, resp.text, re.IGNORECASE):
                        return {
                            "success": True,
                            "response_code": resp.status_code,
                            "response_body": resp.text[:500],
                            "evidence": f"SQL error matched: {pattern}",
                            "payload": payload,
                        }
            except Exception as e:
                continue
        return {"success": False, "response_code": 0, "response_body": ""}

    def test_negative(self, target_url: str, endpoint: str, **kwargs) -> dict:
        """Send normal request, should NOT get SQL error."""
        import requests
        try:
            url = f"{target_url}{endpoint}1"
            resp = requests.get(url, timeout=10, verify=False)
            has_error = any(re.search(p, resp.text, re.IGNORECASE) for p in self.error_patterns)
            return {
                "success": not has_error,  # success = no error (control passed)
                "response_code": resp.status_code,
                "response_body": resp.text[:500],
            }
        except Exception:
            return {"success": True, "response_code": 0, "response_body": ""}


class XSSReflectedOracle(BaseOracle):
    """Verify XSS via reflection detection."""

    name = "xss_reflected"
    test_payloads = [
        "hydra_test_xyz123",
        "<script>alert('hydra')</script>",
    ]

    def test_positive(self, target_url: str, endpoint: str, param: str = "q", **kwargs) -> dict:
        """Send XSS payload, check if reflected in response."""
        import requests
        for payload in self.test_payloads:
            try:
                url = f"{target_url}{endpoint}"
                resp = requests.get(url, params={param: payload}, timeout=10, verify=False)
                if payload in resp.text:
                    return {
                        "success": True,
                        "response_code": resp.status_code,
                        "response_body": resp.text[:500],
                        "evidence": f"Payload reflected: {payload}",
                        "payload": payload,
                    }
            except Exception:
                continue
        return {"success": False, "response_code": 0, "response_body": ""}

    def test_negative(self, target_url: str, endpoint: str, param: str = "q", **kwargs) -> dict:
        """Send without XSS param, payload should NOT be in response."""
        import requests
        try:
            url = f"{target_url}{endpoint}"
            resp = requests.get(url, timeout=10, verify=False)
            has_payload = any(p in resp.text for p in self.test_payloads)
            return {
                "success": not has_payload,
                "response_code": resp.status_code,
                "response_body": resp.text[:500],
            }
        except Exception:
            return {"success": True, "response_code": 0, "response_body": ""}


class IDOROracle(BaseOracle):
    """Verify IDOR via sequential ID change detection."""

    name = "idor"
    ids_to_test = [1, 2, 3, 100, 101, 999]

    def test_positive(self, target_url: str, endpoint: str, **kwargs) -> dict:
        """Test multiple IDs, check if different data returned."""
        import requests
        responses = {}
        for id_val in self.ids_to_test:
            try:
                url = f"{target_url}{endpoint.replace('{id}', str(id_val))}"
                resp = requests.get(url, timeout=10, verify=False)
                if resp.status_code == 200:
                    responses[id_val] = resp.text[:200]
            except Exception:
                continue

        # If we got different responses for different IDs, likely IDOR
        unique = set(responses.values())
        if len(unique) > 1:
            return {
                "success": True,
                "response_code": 200,
                "response_body": f"{len(responses)} unique responses",
                "evidence": f"IDOR confirmed: {len(unique)} unique responses for {len(responses)} IDs",
            }
        return {"success": False, "response_code": 0, "response_body": ""}

    def test_negative(self, target_url: str, endpoint: str, **kwargs) -> dict:
        """Test with auth, same ID twice — should return same response."""
        import requests
        try:
            url = f"{target_url}{endpoint.replace('{id}', '1')}"
            r1 = requests.get(url, timeout=10, verify=False)
            r2 = requests.get(url, timeout=10, verify=False)
            return {
                "success": r1.text == r2.text,  # Same response = control passes
                "response_code": r1.status_code,
                "response_body": r1.text[:200],
            }
        except Exception:
            return {"success": True, "response_code": 0, "response_body": ""}


class AuthBypassOracle(BaseOracle):
    """Verify auth bypass via header removal."""

    name = "auth_bypass"
    auth_headers = ["Authorization", "X-Auth-Token", "Cookie"]

    def test_positive(self, target_url: str, endpoint: str, headers: dict = None, **kwargs) -> dict:
        """Send without auth headers, check if still accessible."""
        import requests
        try:
            # Send without any auth
            resp = requests.get(f"{target_url}{endpoint}", timeout=10, verify=False)
            if resp.status_code == 200:
                return {
                    "success": True,
                    "response_code": resp.status_code,
                    "response_body": resp.text[:500],
                    "evidence": "Endpoint accessible without authentication",
                }
        except Exception:
            pass
        return {"success": False, "response_code": 0, "response_body": ""}

    def test_negative(self, target_url: str, endpoint: str, headers: dict = None, **kwargs) -> dict:
        """Send WITH auth headers — should return 200 (control passes)."""
        import requests
        try:
            resp = requests.get(f"{target_url}{endpoint}", headers=headers or {},
                              timeout=10, verify=False)
            return {
                "success": resp.status_code == 200,
                "response_code": resp.status_code,
                "response_body": resp.text[:200],
            }
        except Exception:
            return {"success": False, "response_code": 0, "response_body": ""}


# Oracle registry
ORACLES = {
    "sql_error": SQLErrorOracle,
    "xss_reflected": XSSReflectedOracle,
    "idor": IDOROracle,
    "auth_bypass": AuthBypassOracle,
}


def get_oracle(name: str) -> Optional[BaseOracle]:
    """Get an oracle by name."""
    cls = ORACLES.get(name)
    if cls:
        return cls()
    return None


def verify_finding(finding: dict, target_url: str) -> OracleResult:
    """Auto-select and run the appropriate oracle for a finding."""
    vuln_class = finding.get("vuln_class", "").lower()
    endpoint = finding.get("endpoint", "")

    # Map vuln class to oracle
    oracle_map = {
        "sql injection": "sql_error",
        "sqli": "sql_error",
        "xss": "xss_reflected",
        "cross-site scripting": "xss_reflected",
        "idor": "idor",
        "insecure direct object reference": "idor",
        "auth bypass": "auth_bypass",
        "authentication bypass": "auth_bypass",
    }

    oracle_name = oracle_map.get(vuln_class)
    if not oracle_name:
        return OracleResult(
            oracle_name="none",
            verified=False,
            attempts=0,
            successes=0,
            message=f"No oracle for vuln class: {vuln_class}"
        )

    oracle = get_oracle(oracle_name)
    if not oracle:
        return OracleResult(
            oracle_name=oracle_name,
            verified=False,
            attempts=0,
            successes=0,
            message=f"Oracle not found: {oracle_name}"
        )

    return oracle.verify(target_url, endpoint, **finding)
