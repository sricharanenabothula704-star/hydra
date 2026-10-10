---
name: detecting-unsafe-reflection-java-gadget-invocation
description: >-
  Detecting Java reflection/Class.forName invocations of attacker-controlled class names (RCE gadget paths). Covers reflection sinks, Spring parameter binding gadgets, and safe fingerprinting.
---

# SKILL: Detecting Java reflection/Class.forName invocations of attacker-controlled class names (RCE gadget paths). Covers reflection sinks, Spring parameter binding gadgets, and safe fingerprinting.

> **AI LOAD INSTRUCTION**: Load when a Java app builds a class name or method from user input and invokes it reflectively (Class.forName, getMethod().invoke, Spring setValue), which is a common RCE gadget path. Covers detection and safe confirmation.

## 0. RELATED ROUTING
- [detecting-java-deserialization-gadget-chain-without-rce](#) for gadget chains
- [exploiting-spring-cloud-function-spel-rce](#) for SpEL reflection
- [exploiting-cwe-94-code-injection-in-template-eval](#) for code injection

## 1. THE SINKS

- `Class.forName(userInput).getMethod("x").invoke(obj)`
- Spring `BeanWrapper.setValue()` / data binding into arbitrary properties
- `ClassPathXmlApplicationContext` loading user XML
- JNDI lookups with user-controlled names (Log4Shell-style)

## 2. SAFE CONFIRMATION

Do NOT invoke `Runtime.exec` on third parties. Confirm the reflection sink benignly: attempt to resolve a harmless known class (`java.lang.String`) and observe behavior, or trigger a distinct error proving the class name is honored. The sink existing with user input is the finding; RCE escalation needs authorization.

## 3. DETECTION

```bash
rg -n "Class\.forName|getMethod\(|getDeclaredMethod\(|\.invoke\(|setValue\(" -g '*.java'
rg -n "ClassPathXmlApplicationContext|XmlBeanFactory" -g '*.java'
```

## 4. FRAMEWORK CONTEXT

Spring Boot Actuator exposes bean/endpoint introspection; combined with a data-binding sink it can escalate. Cover data binding by checking if attacker-controlled request params map to object properties (mass assignment) beyond whitelisted fields.

## 5. REMEDIATION

Never build class/method names from user input. Use an allowlist of permitted types. Disable JNDI lookups where unneeded. Keep Spring data binding to a strict DTO allowlist. Disable Actuator in production.

## Sources
- CWE-470 (unsafe reflection): https://cwe.mitre.org/data/definitions/470.html
- CWE-502: https://cwe.mitre.org/data/definitions/502.html
