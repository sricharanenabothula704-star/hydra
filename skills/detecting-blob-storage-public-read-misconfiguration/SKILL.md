---
name: detecting-blob-storage-public-read-misconfiguration
description: >-
  Assess object storage buckets and containers for anonymous read exposure, permissive ACLs, and policy gaps that publish private data.
---

# SKILL: Assess object storage buckets and containers for anonymous read exposure, permissive ACLs, and policy gaps that publish private data.

> **AI LOAD INSTRUCTION**: Load when auditing cloud storage, reviewing a media upload pipeline, or triaging a suspected exposed object.

## 0. RELATED ROUTING
- [auditing-aws-s3-bucket-permissions](#) for the AWS-specific assessment
- [detecting-secret-management-hardcoded-config-files](#) for secret exposure via public objects
- [detecting-shadow-api-endpoints](#) for undiscovered public surfaces

## 1. THE EXPOSURE MODEL

Cloud object storage is a global, unauthenticated surface by default. The failure mode
is rarely a compromised credential but a bucket made public for one legitimate
purpose, such as static site hosting, and never reverted. Since object keys are
frequently guessable, an open container is effectively an open directory.

## 2. PROVIDER-SPECIFIC MISCONFIGURATIONS

| Provider | Common defect |
|---|---|
| AWS S3 | ACL `public-read` or `public-read-write`; `BlockPublicAccess` disabled; bucket policy `Principal: *` on `s3:GetObject`; website hosting endpoint exposing a private prefix |
| GCS | `allUsers` or `allAuthenticatedUsers` binding on a bucket or object |
| Azure Blob | container `public` access level; or managed identity granting broad blob read |
| Cloudflare R2 / MinIO | Anonymous read enabled; policy allowing unauthenticated `GetObject` |

The compound case matters most: BlockPublicAccess disabled *and* a permissive policy
*and* a public ACL. Any one control configured correctly would have blocked access,
so the combination indicates no single owner of the posture.

## 3. NON-INVASIVE VERIFICATION

Test only buckets you own or have written authorization to assess. Never enumerate
or download objects from a third party's storage, and never fetch objects you have
no permission to assess. Prefer checking configuration over fetching content.

```bash
# AWS: effective public access posture and ACLs
aws s3api get-public-access-block --bucket YOUR-BUCKET
aws s3api get-bucket-acl --bucket YOUR-BUCKET | jq '.Grants[].Grantee'
aws s3api get-bucket-policy --bucket YOUR-BUCKET | jq '.Policy'

# GCS
gcloud storage buckets get-iam-policy gs://YOUR-BUCKET

# Azure
az storage container show --name YOUR-CONTAINER --account-name YOUR-ACCOUNT \
  --query '{publicAccess: publicAccess}'

# Anomaly detection for the whole account, read-only
aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,\
AttributeValue=GetObject --max-results 20
```

To confirm reachability without downloading data, request a single object you
uploaded yourself with an unsigned request and observe the status code:

```bash
curl -s -o /dev/null -w '%{http_code}\n' \
  'https://YOUR-BUCKET.s3.amazonaws.com/YOUR-OWN-TEST-OBJECT.txt'
```

`200` confirms anonymous read. `403` confirms the block is effective. Send
`Range: bytes=0-0` if you need to prove existence without transferring content.

## 4. WHAT TO CHECK BEYOND THE BUCKET

Pre-signed URLs valid for days make objects effectively public to anyone holding
the link. Predictable keys such as sequential ids, customer identifiers, or email
addresses in the path invite enumeration. User-supplied `Content-Disposition` or
CORS headers enable a stored-XSS path if the bucket serves HTML or SVG. A public
web-assets prefix may silently extend to uploads. A delete marker does not remove
prior versions, which remain readable. Without access logs, exposure cannot be
reconstructed.

## 5. PRESIGNED URL REVIEW

```bash
# On a URL you generated yourself for testing, decode the parameters
echo "$URL" | sed 's/[&?]/&\n/g' | grep -E 'X-Amz-Expires|X-Amz-Signature'
```

Flag lifetimes beyond a few minutes for sensitive objects, missing
`X-Amz-Content-Sha256` pinning, and signatures not scoped to a specific method or
content length.

## 6. REMEDIATION

Enable account-level Block Public Access, remove public ACLs, and constrain bucket
policies to named principals or service roles. Move public assets to a dedicated
bucket or CDN origin. Use pre-signed URLs with short lifetimes, generate
unpredictable object keys, and enforce encryption at rest and in transit. Monitor
policy drift with a scheduled check and alert on any ACL or policy change.

## 7. RESPONSIBLE TESTING

Only assess accounts, buckets, and containers you own or are explicitly authorized to
review. Never enumerate keys in a bucket you do not own, never download data you
are not authorized to read, and never obtain more than the single-byte existence
proof needed to confirm exposure. Report it as a configuration defect with a
redacted example key, not as harvested data.

## Sources
- CWE-732: https://cwe.mitre.org/data/definitions/732.html
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- AWS S3 Security: https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html
