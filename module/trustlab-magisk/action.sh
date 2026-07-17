#!/system/bin/sh
MODDIR=${0%/*}
RUNNER="$MODDIR/scripts/run_collection.sh"

if [ ! -x "$RUNNER" ]; then
  echo "Android Trust Lab: collection runner is missing or not executable"
  exit 1
fi

sh "$RUNNER" action
exit $?
