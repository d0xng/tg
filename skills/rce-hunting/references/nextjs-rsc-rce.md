# Next.js RSC deserialization RCE — moved to shared canonical copy

This technique is shared by `rce-hunting` and `deserialization-hunting`. To avoid
duplicating it in two skills, the full reference now lives in one canonical place:

**-> `../../_shared/references/nextjs-rsc-deser.md`**

It covers CVE-2025-55182 (unauth RCE via the multipart Server Action ->
React deserializer -> `child_process.execSync` prototype-pollution gadget) and
CVE-2025-55184 (DoS), including:

- the fingerprint (`x-powered-by: Next.js`, `content-type: text/x-component`,
  `vary: RSC, Next-Router-State-Tree`) and the affected table — 19.2.1 is a FIX,
  and every Next 16.0.0-16.0.6 host is vulnerable despite looking newer;
- the safe 2-step probe (`Next-Action` text/plain -> `404`, then multipart ->
  `500`-with-RSC-body, which is the POSITIVE oracle — do not bail on it);
- the benign-`id` RCE gadget and the `1:E{"digest":"<output>"}` reflection;
- the generalized proof points, dedup anchors, and the
  never-fire-DoS-on-prod rule.

Read the shared file directly.
