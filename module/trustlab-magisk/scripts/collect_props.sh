#!/system/bin/sh
printf '=== GETPROP ===\n'
for KEY in \
  ro.boot.flash.locked \
  ro.boot.vbmeta.device_state \
  ro.boot.verifiedbootstate \
  ro.boot.veritymode \
  ro.build.fingerprint \
  ro.build.version.release \
  ro.build.version.sdk \
  ro.crypto.state \
  ro.crypto.type \
  ro.crypto.volume.filenames_mode \
  ro.product.device \
  ro.product.manufacturer \
  ro.product.model \
  ro.debuggable \
  ro.secure \
  ro.adb.secure \
  sys.boot_completed
do
  VALUE=$(getprop "$KEY" 2>/dev/null)
  printf '[%s]: [%s]\n' "$KEY" "$VALUE"
done
exit 0
