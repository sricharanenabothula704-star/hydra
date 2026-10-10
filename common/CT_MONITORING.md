# : Monitor Bug Bounty Targets in Real Time Using Certificate Transparency Logs
- Source: (Dec 29, 2025) — infosecwriteups.com
- Real-time CT log monitoring for fresh asset discovery

## Why Monitor Certificate Transparency?
Whenever a CA issues an SSL/TLS certificate for a domain, it must be logged in a public CT log.

### Benefits:
- **Discover "Fresh" Assets**: Test subdomains minutes after they are created
- **Avoid Duplicates**: Find bugs before other hunters using static datasets
- **Automate Recon**: Let the tool run 24/7 while you do manual testing

## Crtmon — Real-Time CT Monitoring
Use `crtmon` to watch CT logs in real time and get alerts.

```bash
# Monitor a target continuously
crtmon -d target.com
# Get alerted as soon as new subdomains are issued
```

## Manual CT Log Queries
```bash
# crt.sh query
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
  jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# CertSpotter query
curl -s "https://api.certspotter.com/v1/issuances?domain=target.com&include_subdomains=true&expand=dns_names" | \
  jq -r '.[].dns_names[]' | sort -u

# Censys query (richer syntax)
# Query by organization name (O= field) — catches acquisition domains
```

## Organization Name Pivoting (Advanced)
Instead of querying by domain, query by organization name:
- `O=` field in certificate subject
- Catches new acquisitions, internal portals, beta products
- Companies issue certs for domains not yet publicly linked

## Expired Wildcard Certificate Mining
- An expired wildcard `*.target.com` means they used one cert for everything
- May have switched to per-subdomain certs — gaps exist
- Old infrastructure under wildcard is now piecemeal covered

## Internal CN Value Hunting
- Certificates for internal services sometimes appear in CT logs
- CN field reveals internal naming schemes
- Misconfiguration: internal cert issued by public CA

## Automation Pipeline
```bash
# Continuous monitoring loop
while true; do
  curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u > new_subs.txt

  # Compare with previous run
  comm -23 new_subs.txt previous_subs.txt > fresh_subs.txt

  # Immediately probe fresh assets
  httpx -l fresh_subs.txt -silent | nuclei -t cves/ -t exposures/

  mv new_subs.txt previous_subs.txt
  sleep 3600  # Check every hour
done
```

## Key Tools
- `crtmon` — Real-time CT monitoring (recommended)
- `certstream-server-go` — Alternative to deprecated certstream
- `subfinder` — Queries multiple CT sources
- `ctfr` — Certificate Transparency Fast Recon
- `crt.sh` — Web interface + API
- `Censys` — Rich CT log search
- `CertSpotter` — API-based monitoring
