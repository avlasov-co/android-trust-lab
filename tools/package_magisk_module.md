# Package Magisk Module

From repository root:

```bash
cd module/trustlab-magisk
zip -r ../../androidtrustlab-magisk.zip .
```

Before packaging verify:

```bash
test -f skip_mount
test ! -f system.prop
if find . \( -path './system/*' -o -path './vendor/*' -o -path './product/*' \) -print -quit | grep -q .; then
  echo "Refusing to package: overlay replacement files found."
  exit 1
fi
```

The module must not contain overlay replacement files. It must remain a read-only collector and must not introduce system modifications.

For the MVP, package this as a Magisk-app-only module. Do not include `META-INF/` recovery-installer files. Also verify that `scripts/lib.sh` is absent unless it is actually used and tested.
