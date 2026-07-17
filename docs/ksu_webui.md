# KernelSU WebUI

Android Trust Lab includes a local KernelSU management interface at
`webroot/index.html`. It is supported only by an official KernelSU Manager host
that provides the official JavaScript `spawn` bridge. The bridge is vendored as
`kernelsu` 3.0.2 with SHA-256
`868805848c3a208c79fbf0f7581255a33c33b812dfaae8b457125fbbb2c400ca` under
Apache-2.0; it is never fetched at runtime.

## Use

Install the deterministic module ZIP in KernelSU Manager, reboot, open the
module WebUI, then refresh status. Run collection only when ready; completed
and partial collections remain private under `/data/adb/android-trust-lab`.
Details show sanitized manifest metadata only. Verify a complete collection
before export. Export requires an explicit privacy acknowledgement and writes a
new, non-overwriting directory at:

```text
/sdcard/Download/AndroidTrustLab/<private-collection-id>/
```

Shared storage can be read by other apps and device users according to Android
storage policy. Export is never automatic. Delete requires typing the selected
ID and affects only its private collection, never an export.

The exact API contract is [KernelSU WebUI API v1](ksu_webui_api_v1.md).

## Compatibility

| Host | Status |
| --- | --- |
| Official KernelSU Manager with `spawn` bridge | implementation target; real-device test pending |
| Magisk | no native WebUI claim; Action and boot collection remain available |
| KSUWebUI, WebUI X, MMRL, APatch, other hosts | unverified; no compatibility claim |

If the bridge is absent, the page shows an unsupported-host message and exposes
no privileged controls. A failed collection retains the collector's honest
partial publication behavior. A failed verification means evidence may have
changed or is incomplete; do not export it. An export collision is intentional:
review the existing shared-storage directory rather than overwriting it.

## Real-device checklist (not yet completed)

- [ ] Install the official KernelSU Manager module and reboot.
- [ ] Confirm the module WebUI button is visible and opens.
- [ ] Run a collection, close/reopen the page, inspect, and verify it.
- [ ] Export and import the exported directory with the host importer.
- [ ] Delete a selected private collection; confirm its export remains.
- [ ] Run the Action button and confirm boot-time collection behavior.
- [ ] Confirm the Magisk Action/boot regression path.
- [ ] Test KSUWebUI and WebUI X separately before making any compatibility claim.
