---
name: detecting-cloud-storage-bucket-listing-anonymous-access
description: >-
  Buckets with permissive ACLs or policy grant anonymous ListBucket, exposing every object name, size, and owner across an entire storage prefix.
---

# SKILL: Buckets with permissive ACLs or policy grant anonymous ListBucket, exposing every object name, size, and owner across an entire storage prefix.

> **AI LOAD INSTRUCTION**: Load when reviewing S3/GCS/Azure Blob storage permissions for anonymous enumeration during an authorized cloud exposure audit.

## 0. RELATED ROUTING
- [detecting-blob-storage-public-read-misconfiguration](#) for reading object contents rather than listing them
- [detecting-exposed-database-admin-panel-portal](#) for the datastore that the listing may lead to
- [detecting-api-documentation-swagger-endpoint-exposure](#) for the REST-spec sibling of metadata leakage

## 1. LISTING VERSUS READING

`ListBucket` is distinct from `GetObject`. Many teams correctly block public object
downloads while leaving the listing permission public, and they never notice because
the bucket homepage shows no files without the `list-type=2` query parameter. Once
listed, object keys leak structure: `customers/2019/invoices/INV-0001.pdf`,
`staging/db/dump-latest.sql`, `internal/roadmap/`. Key names alone reveal customer
identifiers, internal project codenames, and the existence of backup artifacts that
can then be tested for public read.

## 2. READ-ONLY LIST PROBE

`GET` on the bucket with `list-type=2&max-keys=1` is the minimal, low-impact probe.
Requesting `max-keys=1` proves permission without enumerating or downloading:

```
curl -s -o /dev/null -w '%{http_code}\n' \
  'https://bucket.s3.amazonaws.com/?list-type=2&max-keys=1'
aws s3api list-objects-v2 --bucket BUCKET --max-keys 1
gcloud storage ls "gs://BUCKET" --max-count 1
az storage blob list --container-name CONTAINER --account-name ACCOUNT --max-results 1
```

A `200` with a `<ListBucketResult>` body containing `<Key>` and `<IsTruncated>` is
conclusive anonymous listing. `403 AccessDenied` means listing is closed.

## 3. DISTINGUISHING LIST FROM READ WITHOUT DOWNLOADING

Use a ranged GET of a single byte on a *nonexistent* key. If the error differs from
the error for an existing key, read permission may be inferable. Note that S3 returns
`NoSuchKey` versus `AccessDenied` inconsistently by policy — the differential is
itself informative but should be reported cautiously:

```
curl -s -o /dev/null -w '%{http_code}\n' 'https://bucket.s3.amazonaws.com/does-not-exist-xyz'
curl -s -r 0-0 -o /dev/null -w '%{http_code}\n' 'https://bucket.s3.amazonaws.com/<known-key>'
```

Prefer the cloud CLIs for attribution, which return the exact grant:

```
aws s3api get-bucket-acl --bucket BUCKET
aws s3api get-bucket-policy --bucket BUCKET
aws s3api get-public-access-block --bucket BUCKET
```

## 4. PROVIDER VARIANTS

- **S3**: legacy ACLs (`AllUsers`/`AuthenticatedUsers` grantee) and bucket policies
  with `Principal: "*"` on `s3:ListBucket`. Note that `BlockPublicAcls` and
  `IgnorePublicAcls` neutralize risky ACLs — check whether they are enabled.
- **GCS**: uniform bucket-level access vs per-object `allUsers`; probe
  `https://storage.googleapis.com/storage/v1/b/BUCKET/o?maxResults=1`.
- **Azure Blob**: anonymous container listing via
  `?restype=container&comp=list&maxresults=1`; check that "Public access" is
  Disabled and that no managed identity grants wide blob roles.
- **MinIO / Ceph**: same S3 semantics with a custom endpoint.

## 5. ASSESSMENT WITHOUT ENUMERATION

You do not need the file list. A `200` on `list-type=2&max-keys=1` combined with a
`200` (or `206`) on a ranged `GetObject` of a single byte establishes the finding at
minimal data cost. Report bucket name, region/account, the anonymous principal, and
the affected actions — not the object inventory.

## 6. REMEDIATION VERIFICATION

- Enable S3 Block Public Access on the account (`BlockPublicAcls`,
  `IgnorePublicAcls`, `BlockPublicPolicy`, `RestrictPublicBuckets`) and set
  PublicAccessBlock on each bucket.
- Remove `AllUsers` and `AuthenticatedUsers` grants; prefer explicit IAM principals
  with conditions.
- Set GCS public access prevention to `enforced` and uniform bucket-level access.
- Set Azure storage accounts to "Public access: Disabled" and remove
  `Storage Blob Data Reader` at container scope for `Microsoft.Storage/storageAccounts`.
- Prefer presigned URLs with short expiry over ACL grants.
- Audit for public listing via CSPM continuously — it is a common regression.

## 7. RESPONSIBLE TESTING

Only test storage you own or are explicitly authorized to assess, and prefer the
cloud CLI with your own scoped role over anonymous probing wherever possible. Always
cap requests with `--max-keys 1` or `maxResults=1`; never enumerate a full bucket or
download object contents — a listing on a production bucket with millions of keys is
a self-inflicted DoS and a large data exposure. Do not fetch objects to prove read
access; a one-byte range request is sufficient. If you use `aws s3api`, scope the
profile and use `--no-sign-request` only for the anonymous probes. Never disable
Block Public Access on a bucket to "test" configuration.

## Sources
- CWE-732: https://cwe.mitre.org/data/definitions/732.html
- CWE-284: https://cwe.mitre.org/data/definitions/284.html
- AWS S3 Block Public Access: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
