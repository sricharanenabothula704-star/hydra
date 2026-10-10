# Tor Usage

## Status: ALWAYS ON (since Jun 29, 2026)
All recon/testing must go through Tor proxy for anonymity.

## Proxy
- Address: 127.0.0.1:9050
- Type: SOCKS5
- Service: `systemctl status tor` (active)

## Curl Usage
```bash
# Use --socks5-hostname flag
curl --socks5-hostname 127.0.0.1:9050 https://target.com
```

## Verification
```bash
curl -s --socks5-hostname 127.0.0.1:9050 'https://httpbin.org/ip'
```


> Target host lists are kept in the private repository.
