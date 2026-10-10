---
name: detecting-exposed-devops-tooling-ci-cd-endpoint
description: >-
  Exposed Jenkins, GitLab Runner, Argo CD, Drone, Gitea, or CI dashboards hand attackers build execution, secret stores, and deployment keys.
---

# SKILL: Exposed Jenkins, GitLab Runner, Argo CD, Drone, Gitea, or CI dashboards hand attackers build execution, secret stores, and deployment keys.

> **AI LOAD INSTRUCTION**: Load when assessing build and deployment infrastructure for internet-reachable consoles in an authorized external review.

## 0. RELATED ROUTING
- [detecting-exposed-database-admin-panel-portal](#) for the sibling admin-portal class
- [detecting-exposed-monitoring-dashboard-public-access](#) for the observability half of the same estate
- [detecting-origin-server-bypass-cdn-security-misconfig](#) for reaching internal tooling via origin

## 1. WHY DEVOPS TOOLING IS A HIGH-VALUE TARGET

CI/CD servers sit at the highest-trust point in the estate. A compromised Jenkins or
GitLab instance can read pipeline variables, which routinely contain cloud keys and
database passwords, then execute arbitrary build steps on agents — which in turn
reaches production. Argo CD or Flux with an exposed API server grants cluster
admission, which is equivalent to root on the cluster. These consoles are often
placed on public IPs for webhook delivery from third-party SaaS, which is exactly the
design mistake that creates the exposure.

## 2. PASSIVE DISCOVERY

Fingerprint by headers and body markers, not by banner scanning alone. Paths and
ports:

```
for p in /jenkins/ /gitlab/ /gitea/ /drone/ /argocd/ /sonarqube/ /nexus/ \
         /artifactory/ /concourse/ /woodpecker/ /buildkite/ /teamcity/; do
  curl -s -o /dev/null -w "%{http_code} %{size_download} $p\n" "https://target.example$p"
done
curl -sI https://target.example:8080/ | grep -iE 'x-jenkins|x-hudson|location'
curl -sI https://target.example:8082/ | grep -iE 'server|location'   # Drone / Gitea
curl -s https://target.example:8080/login | grep -ioE 'jenkins|hudson' | head -3
```

Reliable markers: `X-Jenkins`, `X-Hudson`, Jenkins crumb issuer at `/crumbIssuer/api/json`,
GitLab's `/users/sign_in`, Argo CD's asset-path redirect to `/auth/login`, Drone's
`X-Drone-Token` challenge, Nexus/Artifactory's `/service/rest/v1/status`.

## 3. THE PASSIVE ENDPOINTS THAT DECIDE EXPOSURE

Most of these platforms have unauthenticated status endpoints. A 200 on them proves
the console is live and versioned, with no login attempt:

```
curl -s -o /dev/null -w '%{http_code}\n' https://jenkins.example.com/login
curl -s https://jenkins.example.com/crumbIssuer/api/json | head -c 200
curl -s https://gitlab.example.com/-/health | head -c 200
curl -s https://argocd.example.com/api/version
curl -s https://nexus.example.com/service/rest/v1/status
curl -s https://artifactory.example.com/artifactory/api/system/version
```

Argo CD with `server.insecure=true` disables authentication entirely — `GET /api/v1/session`
returning a populated user object with no cookie is conclusive.

## 4. EXPOSED RUNNER OR AGENT RISK

An unauthenticated CI runner registration port (`gitlab-runner` on 9252, Drone on
8080 with a shared token, a Jenkins inbound agent port on 50000) is worse than an
exposed UI because it permits job submission. Detect by connect-only checks and by
the agent registration UI responding:

```
nmap -sT -p 8080,9252,50000,6443,2379 target.example.com
```

Port `2379` (etcd) or `6443` (apiserver) reachable from the internet is an
independent critical finding — check with `curl -sk https://host:6443/version`, which
returns version info without credentials on many clusters.

## 5. REMEDIATION VERIFICATION

- Place all CI/CD consoles on a private subnet or behind SSO + VPN.
- Never expose a console for webhook convenience — use a relay or an inbound
  webhook proxy instead.
- Move pipeline secrets into a vault or an external secret store, never into
  environment variables visible to build logs.
- Disable anonymous read on Jenkins (`anonymousRead=false`) and GitLab public
  projects.
- Scope runner registration tokens, rotate them, and require registration approval.
- Rotate any secret that was ever visible in a pipeline log.

## 6. RESPONSIBLE TESTING

Only test systems you own or are explicitly authorized to test. Probe only
unauthenticated status and version endpoints — never submit a login, never attempt
to register a runner or agent, and never queue or trigger a build, which would
execute code on production agents. Do not enumerate job history, credentials
bindings, or user directories. Avoid broad automated scanners against CI platforms;
they frequently attempt default logins and will pollute audit trails and lock out
accounts. Report the console URL, version banner, and which endpoints returned 200.

## Sources
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- CWE-306: https://cwe.mitre.org/data/definitions/306.html
- OWASP CI/CD Security guidance: https://cheatsheetseries.owasp.org/cheatsheets/Continuous_Integration_Cheat_Sheet.html
