---
name: js-analysis
description: JavaScript bundle analysis for API endpoints, secrets, and application logic
---

## JS Analysis Methodology

### Extraction
```bash
# From HTML page
curl -sk "https://target.com/" | grep -oP 'src="([^"]+\.js[^"]*)"'

# Download and analyze
curl -sk "https://target.com/chunk.js" -o /tmp/analyze.js
```

### Pattern Searching
```python
import re, json

c = open("/tmp/analyze.js").read()

# API endpoints
for m in re.findall(r'["\'](/v[12]/[^"\']+)["\']', c):
    print(f"Endpoint: {m}")

# API base URLs
for m in re.findall(r'(?:baseURL|apiUrl|BASE_URL)["\']?\s*[:=]\s*["\']([^"\']+)["\']', c):
    print(f"API Base: {m}")

# Secrets and tokens
for m in re.findall(r'(?:key|secret|token|api[_-]?key)[:=]["\']?([A-Za-z0-9_\-]{20,})["\']?', c, re.I):
    print(f"Potential secret: {m}")

# Routes
for m in re.findall(r'["\'](/[a-z-]+(?:/[a-z-]+)*)["\']', c):
    if any(x in m.lower() for x in ['api', 'auth', 'order', 'trade', 'admin', 'login']):
        print(f"Route: {m}")
```

### Next.js Specific
- Look for __NEXT_DATA__ in HTML for build ID and page props
- Download _next/static/chunks/pages/ for page-specific code
- Check _buildManifest.js for route listing
