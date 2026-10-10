# Scope Reference — Working Template

> Copy this file per-program and fill in scope from the official program page.
> Never commit real client/target scope data to public repos.

## <PROGRAM NAME> (`hackerone.com/<handle>`)

| Asset | Type | Criticality | In Scope | Notes |
|-------|------|-------------|----------|-------|
| `api.example.com` | URL | High | yes | |
| `*.example.dev` | Wildcard | Medium | partial | exclude staging |

## Rapid Scope Check Commands
```bash
# confirm target resolves in-scope before ANY packet
dig +short <host>
curl -sI https://<host> | head -5
```

## Key Takeaways Template
- Scope source & date checked:
- Explicit exclusions:
- Rate-limit policy:
- Safe-harbor language present: yes/no
