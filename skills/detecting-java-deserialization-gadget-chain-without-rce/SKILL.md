---
name: detecting-java-deserialization-gadget-chain-without-rce
description: >-
  Identify Java deserialization gadget chains in a classpath without ever detonating one, using passive classpath analysis, gadget-chain mapping, and non-executing probes.
---

# SKILL: Identify Java deserialization gadget chains in a classpath without ever detonating one, using passive classpath analysis, gadget-chain mapping, and non-executing probes.

> **AI LOAD INSTRUCTION**: Load when a Java app calls readObject/readUnshared/ObjectInputStream, uses fastjson/Jackson/XStream/YAML-snakeyaml, or accepts serialized Base64 blobs.

## 0. RELATED ROUTING
- [deserialization-insecure](#) for the generic Java deserialization surface
- [detecting-java-deserialization-gadget-chain-without-rce](#) for safe classpath triage
- [exploiting-java-log4j-jndi-family](#) for the sibling JNDI lookup family (separate flaw class)

## 1. WHY NON-EXECUTION MATTERS

A gadget chain only proves impact if a chain actually resolves and runs. Firing `TemplatesImpl.newTransformer()` chains on a target is destructive, noisy, and legally fraught. The defensible approach is to prove three separate facts and report them separately:

1. **Sink exists** — untrusted bytes reach `ObjectInputStream.readObject()`.
2. **Classpath contains gadget ingredients** — the JDK gadget libraries are present.
3. **A chain assembles** — offline, in a sandbox, from the *actual* dependency set.

Any two of the three is a high-severity finding. None require executing on the target.

## 2. CONFIRMING THE SINK (BENIGN)

Look for `Content-Type: application/x-java-serialized-object`, `application/x-java-serialized-object;charset=UTF-8`, or endpoints accepting Base64 that decodes to magic bytes:

```
AC ED 00 05   <- Java serialization stream magic (readObject-ready)
```

Benign confirmation probes:

- Send `rO0AB` (Base64 of a minimal valid stream). A 500 with a stack trace naming `ObjectInputStream` confirms the sink.
- Send random garbage; a *different* exception than the valid stream confirms the server actually parses (discriminating oracle).
- Compare behavior with `Content-Type: application/json` — a divergence proves type-driven deserialization.

## 3. PASSIVE CLASSPATH FINGERPRINTING

Ask for the artifact inventory, then map libraries to gadget roles.

| Gadget library | Typical role | Trigger surface |
|---|---|---|
| Commons Collections 3.2.x | `InvokerTransformer` -> `ConstantTransformer` -> `ChainedTransformer` | any |
| Commons Beanutils 1.x | `BeanComparator` + `TemplatesImpl` | any |
| Groovy 2.x | `MethodClosure` -> `MethodInvokeTransformer` | Groovy apps |
| Spring Framework 5.8-5.9.x / 6.0.0-6.0.11 | `Jdk7u21` / `Jdk8u20` chains | Spring apps |
| Hibernate5, Rome, C3P0, Jython, BeanShell | secondary gadgets | specific frameworks |

Grep the resolved dependency tree:

```
mvn dependency:tree -Dincludes='commons-collections:*,commons-beanutils:*,org.apache.groovy:*,org.springframework:spring-*'
pip-audit   # for the Jython/BeanShell transitive case
```

Lockfiles are the fastest source: `grep -E 'commons-collections|commons-beanutils|groovy' package-lock.json`.

## 4. OFFLINE CHAIN ASSEMBLY (SANDBOX ONLY)

In an isolated container with **no network egress**, load the target's exact jars into `ysoserial` and enumerate:

```
java -jar ysoserial.jar CommonsCollections6   # probe by probe
```

Probing is non-executing until you ask for a side effect. For confirmation, use `CommonsBeanutils1` with a harmless sink that writes a file you then read back:

```
# benign marker write instead of reverse shell
{"@type":"java.lang.Class","val":"..."}   # informational only
```

Better still: use **`URLDNS`** — it triggers exactly one DNS lookup to a host you control, touching no file, no process, no shell. If the DNS query arrives, the full deserialize path executed. This is the standard authorized OOB confirmation.

```
java -jar ysoserial.jar URLDNS http://<oob-domain>.canary.tld
```

## 5. SCORING THE FINDING

| Sink reachable | Gadgets present | Severity |
|---|---|---|
| No | No | Informational (latent risk) |
| Yes | No | Medium — brittle, needs a dependency change |
| No | Yes | Low/Medium — one insecure endpoint away |
| Yes | Yes | **Critical** — no further exploit needed to demonstrate |

A critical row can be closed with zero payload execution: the sink plus the classpath is the proof.

## 6. RESPONSIBLE TESTING

- Never send an executing chain (`CommonsCollections1/5/7`, `BeanShell`, `Jython`) to a production host. Use `URLDNS` OOB or a local canary instance.
- Confirm with a **negative control** first: send a known-broken stream, verify no OOB callback fires, then send the probe. Without this you cannot distinguish your payload from unrelated traffic.
- If a real serializer gadget is required for a pentest deliverable, run it against a self-hosted replica of the app, not the client's production.
- Report the *chain* as demonstrated offline, and the *sink* as demonstrated online — the report then needs no live exploitation at all.

## 7. REMEDIATION

- Replace native serialization with JSON/protobuf; if native is required, use `ObjectInputFilter` (JEP 290) allowlists.
- Apply JEP 290 globally: `-Djdk.serialFilter=...` with a strict class allowlist, not a blacklist.
- Remove the gadget libraries you do not use — most are transitive and unused at runtime.
- On Jackson: keep `PolymorphicTypeValidator` enabled and base-type-constrained. Never enable `enableDefaultTyping()`.

## Sources
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
- OWASP Deserialization Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html
- JEP 290 Filtered Deserialization: https://openjdk.org/jeps/290
- ysoserial project (offline payload reference): https://github.com/frohoff/ysoserial