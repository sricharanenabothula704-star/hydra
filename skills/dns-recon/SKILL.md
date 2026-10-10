---
name: dns-recon
description: DNS reconnaissance methodology for finding subdomains, DNS leaks, and infrastructure mapping
---

## DNS Recon Methodology

### Subdomain Discovery
```bash
# Certificate transparency
curl -sk "https://crt.sh/?q=%25.target.com&output=json"

# DNS brute force common subdomains
for sub in dev staging api admin portal jenkins grafana prometheus alertmanager; do
  dig +short A "$sub.target.com"
  dig +short CNAME "$sub.target.com"
done

# Check CNAME for takeover
dig +short CNAME "$sub.target.com" | xargs -I{} dig +short A {}
```

### DNS Leak Detection
- Look for RFC1918 private IPs in public DNS responses
- Common private ranges: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
- Check staging/dev/uat/internal subdomains specifically

### Infrastructure Mapping
- NS records for DNS provider identification
- MX records for email provider
- TXT records for SPF, DKIM, verification tokens
- CNAME records reveal cloud services (CloudFront, S3, GCS, ALB)
