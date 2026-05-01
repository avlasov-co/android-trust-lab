# Package Magisk Module

Use the checked-in packaging helper from the repository root:

```bash
python tools/package_magisk_module.py --check-only
python tools/package_magisk_module.py --output dist/androidtrustlab-magisk.zip
```

The helper validates required module files and refuses payloads that would turn the module into a system-modification package.

## Safety constraints enforced

The package must not contain:

- `META-INF/`
- `system.prop`
- `scripts/lib.sh` unless it is actually introduced and tested later
- embedded `.zip` files
- overlay or replacement paths under `system/`, `vendor/`, `product/`, `system_ext/`, or `odm/`

The module must remain a read-only collector. It must not introduce property modification, SELinux patching, remount helpers, overlay replacement files, root hiding, identity spoofing, or app-specific evasion logic.

## Manual fallback

If the Python helper is unavailable, package only the module root contents:

```bash
cd module/trustlab-magisk
zip -r ../../androidtrustlab-magisk.zip .
```

Before using a manually created archive, run the same safety checks above by inspection and run `sh -n` on every `*.sh` file.
