"""Low-impact HTTP security-header audit, gated by the local scope allowlist."""

from __future__ import annotations

from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from .scope_policy import DEFAULT_ALLOWLIST, require_scope


class _NoRedirect(HTTPRedirectHandler):
    """Do not follow redirects: the Location host may be outside scope."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class SecurityMisconfigurationScanner:
    """Send one scoped HEAD request and report missing security headers."""

    def __init__(self, timeout: float = 8.0, allowlist_path=None):
        self.timeout = timeout
        self.allowlist_path = allowlist_path or DEFAULT_ALLOWLIST

    def scan(self, target: str) -> dict:
        host = require_scope(target, self.allowlist_path)
        candidate = target if "://" in target else f"https://{target}"
        parsed = urlsplit(candidate)
        if parsed.scheme.lower() not in ("http", "https"):
            raise ValueError("only http:// and https:// targets are supported")
        if not parsed.netloc:
            raise ValueError("target URL must include a host")
        # Scan only the origin root, not a user-provided path with possible
        # application side effects. Never follow redirects to a second host.
        url = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
        request = Request(
            url,
            method="HEAD",
            headers={"User-Agent": "HYDRA-Safe-Header-Audit/0.3.0"},
        )
        opener = build_opener(_NoRedirect())
        try:
            response = opener.open(request, timeout=self.timeout)
        except HTTPError as exc:
            # A 3xx is recorded but not followed; other HTTP codes still carry
            # useful headers and are safe to inspect.
            response = exc
        except (URLError, TimeoutError, OSError) as exc:
            return {
                "target": host,
                "url": url,
                "error": f"HEAD request failed: {exc}",
                "requests_sent": 1,
                "findings": [],
            }

        headers = {k.lower(): v for k, v in response.headers.items()}
        findings = []
        checks = [
            ("Content-Security-Policy", "content-security-policy"),
            ("X-Content-Type-Options", "x-content-type-options"),
            ("Referrer-Policy", "referrer-policy"),
            ("Permissions-Policy", "permissions-policy"),
        ]
        if parsed.scheme.lower() == "https":
            checks.append(("Strict-Transport-Security", "strict-transport-security"))
        for display, key in checks:
            if not headers.get(key):
                findings.append(
                    {"check": display, "severity": "low", "status": "missing"}
                )
        csp = headers.get("content-security-policy", "").lower()
        if not headers.get("x-frame-options") and "frame-ancestors" not in csp:
            findings.append(
                {
                    "check": "Frame embedding protection",
                    "severity": "low",
                    "status": "missing",
                }
            )

        status = getattr(response, "status", None) or getattr(response, "code", None)
        response.close()
        return {
            "target": host,
            "url": url,
            "http_status": status,
            "requests_sent": 1,
            "redirects_followed": 0,
            "headers_checked": [name for name, _ in checks]
            + ["X-Frame-Options / CSP frame-ancestors"],
            "findings": findings,
            "summary": f"{len(findings)} missing header protections; one HEAD request only.",
        }
