# : S3 Bucket Recon — Finding Exposed AWS Buckets Like a Pro
- Source: (Feb 26, 2025) — infosecwriteups.com
- Complete S3 bucket discovery and exploitation methodology

## S3 Bucket URL Formats
```
# Standard format
https://[bucket-name].s3.amazonaws.com
https://s3.amazonaws.com/[bucket-name]/

# Regional format
https://[bucket-name].s3-[region].amazonaws.com
https://[bucket-name].s3.[region].amazonaws.com
```

## Discovery Methods

### 1. Google Dorking
```bash
site:s3.amazonaws.com "target.com"
site:s3.amazonaws.com filetype:xls password target.com
site:s3.amazonaws.com filetype:txt password target.com
site:s3.amazonaws.com filetype:sql target.com
site:s3.amazonaws.com inurl:backup target.com
site:s3.amazonaws.com intext:apikey target.com
site:s3.amazonaws.com ext:log target.com
```

### 2. JavaScript Extraction
```bash
# Gospider detects S3 URLs in page sources
gospider -d 3 -s https://target.com | grep -Eo 'https?://[^"<> ]+\.s3\.amazonaws\.com[^"<> ]*' | sort -u

# java2s3 tool: extract S3 URLs from JS files
cat urls.txt | java2s3
```

### 3. HTTPX + Nuclei
```bash
httpx -l subs.txt -silent | nuclei -t exposures/s3-bucket.yaml
```

### 4. GitHub Dorking
Search GitHub for S3 URLs containing target domain name patterns:
```bash
git dork: filename:.env "s3" "target"
git dork: "s3.amazonaws.com" "target"
```

### 5. Brute-Forcing with LazyS3
```bash
lazys3 target.com
# Automatically tests permutations: target-dev, target-backup, target-assets, etc.
```

### 6. S3Scanner + Cewl
```bash
cewl -d 3 https://target.com | s3scanner -o buckets.txt
```

### 7. Chrome Extension: S3BucketList
Scans web pages for exposed S3 URLs automatically.

## Permission Testing
```bash
# Check listing
aws s3 ls s3://bucket-name --no-sign-request

# Check read
aws s3 cp s3://bucket-name/file.txt . --no-sign-request

# Check write (attempt upload)
echo "test" | aws s3 cp - s3://bucket-name/poc.txt --no-sign-request

# Check all permissions
aws s3api get-bucket-acl --bucket bucket-name --no-sign-request
aws s3api get-bucket-policy --bucket bucket-name --no-sign-request
```

## Exploitation
- List all files: enumerate for sensitive data (DB dumps, configs, credentials)
- Upload: place malicious files (phishing pages, JS backdoors)
- Modify: overwrite existing files with malicious versions
- Delete: denial of service

## Prevention
- Block public access at account level
- Use bucket policies with strict conditions
- Enable S3 Block Public Access
- Audit permissions regularly with tools like S3Scanner
