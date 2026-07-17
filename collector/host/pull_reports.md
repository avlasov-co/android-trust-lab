# Transfer and Import Reports

Magisk collections are written beneath the private on-device path:

```text
/data/adb/android-trust-lab/reports/
```

Transfer an individual collection directory only through an already-authorized,
read-only interface available to the target owner. Android Trust Lab does not
invoke `su`, change permissions, install Magisk, or make this root-owned path
ADB-readable. Do not weaken the collector's private modes to facilitate transfer.

Once the directory is local and unpacked, import it with:

```bash
trustlab import magisk --input LOCAL_COLLECTION_DIR --output PRIVATE_IMPORT_ROOT
```

The importer accepts the directory or its exact `collector_manifest.json`. It
does not accept or extract archives. The source directory must contain only the
completion manifest and its declared evidence files. Incomplete transfers,
extra files, symlinks, special files, and size/hash mismatches are rejected
before normalization or publication.

ADB-shell collections use `trustlab collect adb`; they are not Magisk imports.
