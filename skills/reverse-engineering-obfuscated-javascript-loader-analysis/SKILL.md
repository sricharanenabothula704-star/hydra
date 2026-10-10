---
name: reverse-engineering-obfuscated-javascript-loader-analysis
description: >-
  Recovers readable source from obfuscated JavaScript loaders by decoding string-array rotators, undoing control-flow flattening, and unpinning self-defending anti-debug traps.
---

# SKILL: Recovers readable source from obfuscated JavaScript loaders by decoding string-array rotators, undoing control-flow flattening, and unpinning self-defending anti-debug traps.

> **AI LOAD INSTRUCTION**: Load when a JS bundle or loader resists reading — `_0x` identifiers, a giant string array, a `switch` state machine — and you need to analyse it on a system you are authorized to test.

## 0. RELATED ROUTING
- [deobfuscating-javascript-malware](#) for the malware-analysis framing of the same techniques
- [reverse-engineering-malware-with-ghidra](#) for when the real logic lives in a native module
- [detecting-exposed-secret-embedded-in-frontend-bundle](#) for the extraction payoff once strings decode
- [reverse-engineering-vm-protected-binary-bytecode-dispatch](#) for the native-binary analogue of a JS VM loader

## 1. RESPONSIBLE USE AND SAFE EXECUTION

Analysing obfuscated JavaScript you encountered legitimately — your own bundle, a package you audit, a
malware sample you are authorised to triage, a CTF challenge — is straightforward work. The obligation
is operational: **obfuscated code is arbitrary code, so treat it as hostile while unreadable.** Never
`node payload.js` on your workstation; execute in a throwaway container with no network, a read-only
filesystem, a non-root user, and CPU/memory caps. Hash the original bytes first.

```bash
$ sha256sum bundle.js | tee evidence.txt
$ docker run --rm --network none --read-only --memory 256m -v "$PWD:/w:ro" \
      node:20-alpine node -e 'require("/w/bundle.js")'
```

## 2. THE LAYER TAXONOMY

Obfuscators compose independent transforms, and the order matters. **Literal encoding** turns strings
into hex/base64/`\x`-escapes. **String-array extraction plus a rotator** moves them into one array read
through a decoder function with a per-call offset — the highest-value layer to undo. **Identifier
mangling** renames everything to `a`, `b`, `_0x4f2a`. **Control-flow flattening** replaces function
bodies with a `switch` over a state variable driven by a `while(true)` dispatcher. **Dead-code
injection** adds opaque predicates like `if (!![] === true)`. **Self-defending and anti-debug** code
adds `debugger` statements, `Function('return this')()` identity checks, and checksums over `toString`.
Do them out of order and you waste effort: a rotator you have not decoded will not tell you which
flattened block is dead.

## 3. THE STRING-ARRAY ROTATOR, CONCRETELY

The tell-tale shape is an IIFE that shuffles a literal array until a computed checksum parses, then a decoder function that every string access routes through:

```js
var _0x3f21 = ['aGVsbG8=', 'dG9rZW4=', 'ZXBpYw=='];
(function (_0x1a2b, _0x3c4d) {          // push(shift(...)) until the checksum matches
  var _0x5e6f = function (_0x9) { return _0x3f21[_0x9 - 0x1a4]; };
  while (true) { try { if (checksum() === _0x3c4d) break; else _0x3f21.push(_0x3f21.shift()); }
                  catch (_0x7) { _0x3f21.push(_0x3f21.shift()); } }
})(_0x3f21, 0x1f4a3);
```

Deobfuscation is therefore: evaluate the rotator **once** to settle the array order, then replace every call site with the literal it resolves to. Never reason about the offset arithmetic by hand — the offsets are exactly what the rotator establishes.

## 4. WORKFLOW: STATIC FIRST, DYNAMIC ONLY WHEN NEEDED

```bash
$ npx prettier --parser babel bundle.js > bundle.pretty.js   # formatting, not deobfuscation
$ npx webcrack bundle.js -o deobfuscated/                    # strings + unminify + deobfuscate
$ npx synchrony bundle.js                                    # strong on control-flow flattening
```

`webcrack` and `synchrony` together handle most commercial loaders in one pass. When they stall the
blocker is usually self-defending code, so go dynamic — and instrument the decoder rather than
reverse-engineering it, because it is a real function that computes the answer for you:

```js
// injected inside the sandbox container, before the payload
const _e = globalThis.eval, _f = globalThis.Function;
globalThis.eval = function (s) { console.error('[eval]', String(s).slice(0, 200)); return _e(s); };
globalThis.Function = function (...a) { console.error('[Function]', a[0]); return _f(...a); };
```

Logging every `eval`/`Function` body is often enough: unpacked stage-two source arrives as a string argument and can be written straight to disk for the next pass.

## 5. AST TRANSFORMS BEAR REGEX

Regex fails because identifiers are meaningless; the AST does not care. With Babel you rename by *binding*, which is both safe and reversible:

```js
const parser = require('@babel/parser'), traverse = require('@babel/traverse').default;
const ast = parser.parse(src, { sourceType: 'script' });
traverse(ast, { CallExpression(p) {                 // _0x2b('0x1f4','kQ9') -> its literal
  if (p.node.callee.name === '_0x2b') p.replaceWith(t.stringLiteral(decode(p.node.arguments)));
}});
```

Rename with `scope.rename(oldId, newId)` for readable output, prune dead branches by evaluating constant conditions from the AST rather than source text, and use `recast` to preserve original formatting for diffing or `escodegen` for compact normalised output.

## 6. ANTI-DEBUG TRAPS TO EXPECT

`debugger` statements are trivial and noisy — strip them in the AST pass. The ones that cost real time are self-defending checks. **Function identity:** `Function('return this')()` compared against `window`; break the comparison or the code silently takes the wrong branch. **`toString` checksums:** the file hashes its own source and re-obfuscates or halts on mismatch — and Prettier changes whitespace, so patch the checksum to a constant *before* beautifying. **Timing:** `performance.now()` deltas around a `debugger`; neutralise `performance` and `Date`. **Console tampering:** overriding `console.log` to a no-op — harmless, but it suppresses your logging too, so use `process.stderr`.

## 7. WHAT TO REPORT

The deliverable is not "it is obfuscated", which is an observation. Report the decoded strings of interest (endpoints, keys, feature flags), the unpacking mechanism so a future version can be triaged faster, and whether the obfuscation altered observable behaviour. Treat client-side obfuscation as obfuscation rather than a control — any value enforced only in the bundle is attacker-controlled — and pair this with a server-side authorization review, which is the actual fix.

## Sources
- CWE-95 (Eval Injection): https://cwe.mitre.org/data/definitions/95.html
- CWE-710 (Improper Coding Standards): https://cwe.mitre.org/data/definitions/710.html
- webcrack (modular JS deobfuscator): https://github.com/j4k0xb/webcrack
- synchrony (JS deobfuscator): https://github.com/Osmosis/synchrony
- Babel parser API: https://babeljs.io/docs/babel-parser
