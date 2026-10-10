---
name: detecting-nodejs-vulnerable-gadget-libraries
description: >-
  Identify which npm packages in a Node.js dependency tree can serve as prototype-pollution, child_process, or deserialization gadget amplifiers, without executing any gadget.
---

# SKILL: Identify which npm packages in a Node.js dependency tree can serve as prototype-pollution, child_process, or deserialization gadget amplifiers, without executing any gadget.

> **AI LOAD INSTRUCTION**: Load when you have a package-lock.json / node_modules tree and need to know if a prototype-pollution bug is reachable to RCE through transitive libraries.

## 0. RELATED ROUTING
- [exploiting-cwe-1321-prototype-pollution-node-rce](#) for the pollution-to-RCE technique itself
- [prototype-pollution](#) for the core prototype-pollution testing playbook
- [analyzing-sbom-for-supply-chain-vulnerabilities](#) for full dependency CVE correlation

## 1. WHY THE GADGET INVENTORY MATTERS

Prototype pollution alone is Medium. It becomes Critical only if another installed package *reads* the polluted key. There is no single exploit here — it is a reachability question: `polluted key -> read by library X -> sink in X -> RCE`. Find the sinks first, then the readers; neither step requires running a gadget.

## 2. STEP 1: POLLUTION SINKS

Pollution sinks are functions that merge attacker objects into a prototype. Find them in the tree:

```
grep -rn --include=*.js -E '\[(__proto__|constructor\.prototype|prototype)\]' node_modules | head
grep -rn --include=*.js -E 'function\s+\w*(merge|extend|assign|defaults)\w*\s*\(' node_modules | head -50
```

| Package (vulnerable range) | Mechanism |
|---|---|
| `lodash` < 4.17.19 | `_.merge`, `_.set`, `_.defaultsDeep`, `_.zipObjectDeep` |
| `deepmerge` < 4.2.2 | `merge()` recurses without key blocking |
| `hoek` / `@hapi/hoek` < 4.3.1 | `merge()` |
| `extend` < 3.0.2 | shallow `extend()` |
| `set-value`, `is-mergeable-object` (qs chain) | recursive merge onto `Object.prototype` |
| `find-my-way`, `path-to-regexp` | query-string object becomes an options merge |

```
npm ls lodash deepmerge extend hoek --all
```

## 3. STEP 2: GADGET READERS

Once `Object.prototype` carries an attacker key, look for packages that **read** a well-known key and pass it to a dangerous sink.
**`child_process` gadget chain.** Any library that spawns a command from a config/env-derived options object is a reader: `shelljs` (`shell.exec` -> `/bin/sh`), `execa` (with `shell: true`), `node-cmd`, plus build tooling (`gulp`, `grunt`, `webpack` loaders) that pass options through.

```
grep -rn --include=*.js -E "require\(['\"]child_process['\"]\)" node_modules | head -40
grep -rn --include=*.js -E '\.exec(Sync)?\s*\(' node_modules | grep -v test | head
```

**Specific pollution->RCE gadgets (polluted key -> sink):**

| Polluted key | Reader | Sink |
|---|---|---|
| `argv0` | `child_process` / `cross-spawn` option merge | `execve` argv control |
| `shell` | any lib passing options to `spawn` | forces shell interpretation |
| `env.NODE_OPTIONS` | `child_process` env merge | `--require` preload -> RCE |
| `NODE_OPTIONS` | npm/yarn lifecycle | `--require=evil.js` |
| `path`, `cwd`, `uid`, `gid` | spawn option merges | arbitrary file write / privilege |

The `env.NODE_OPTIONS` vector is the cleanest: pollute `Object.prototype.env.NODE_OPTIONS = '--require /tmp/x.js'`, then trigger any `spawn`. The child loads your file.

## 4. STEP 3: CONFIRMING A SINK WITHOUT A GADGET

You do not need the reader to prove the gadget exists. Two non-executing proofs:

**(a) Offline prototype-pollution unit test.** In a scratch dir with a copy of the target's `node_modules`:

```js
require('lodash').set({}, '__proto__.polluted', 1);
console.log('polluted:', ({}).polluted === 1);   // true => sink confirmed
```

This runs on **your** machine against **your** copy. No target contact.

**(b) Canary-key reachability.** Instead of a dangerous key, pollute with an inert marker and see whether the app's behavior changes:

```js
{ "__proto__": { "canaryProbeKey": "BENIGN-123" } }
```

If the app echoes that key anywhere in its rendered output or JSON response, it is consuming `Object.prototype` — a strong, benign proof of pollution reach with zero side effects.

## 5. STEP 4: STATIC REACHABILITY CHECK

Ask for the routes that touch the merge. The vulnerable shape is user data flowing into a merge and the result being returned:

```js
app.post('/api', (req, res) => {
  _.merge(config, req.body);   // sink: user -> global object
  res.json(config);            // leak: polluted config reflected
});
```

If `req.query`, `req.body`, or a decoded JWT claim reaches a merge/set/assign, the pollution path is open and the gadget question becomes one of severity only.

## 6. CONFIRMING RESPONSIBLY

- Prove pollution with an inert **canary key**, not with `argv0`/`shell`/`NODE_OPTIONS`.
- Only with explicit RCE authorization use a spawn gadget — a nonce file in a temp path you clean up, or one OOB DNS callback. No reverse shell on a production Node app.
- On serverless (Lambda), `NODE_OPTIONS` is far more damaging — flag it as its own Critical finding. Never run the offline unit test against the target's live process.

## 7. REMEDIATION

- Update the merge libraries to fixed versions (lodash >= 4.17.21, deepmerge >= 4.3.1, extend >= 3.0.2, hoek >= 4.3.1 or remove).
- Reject `__proto__`, `constructor`, and `prototype` as keys at the request boundary; validate with `ajv`/`zod` using `additionalProperties: false`.
- Consider `Object.freeze(Object.prototype)` at boot (breaks some libs — test first).
- Never pass user objects into option-merging APIs; build explicit allowlisted option objects. Audit CI tooling for `NODE_OPTIONS` injection via env inheritance.

## Sources
- CWE-1321: https://cwe.mitre.org/data/definitions/1321.html
- OWASP Prototype Pollution Prevention Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Prototype_Pollution_Prevention_Cheat_Sheet.html
- Node.js security best practices (child_process): https://nodejs.org/en/learn/getting-started/security-best-practices
- CVE-2020-8203 (lodash prototype pollution): https://nvd.nist.gov/vuln/detail/CVE-2020-8203