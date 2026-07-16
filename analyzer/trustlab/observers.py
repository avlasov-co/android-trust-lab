"""Canonical observer registry for normalization and CLI surfaces."""

from __future__ import annotations

from dataclasses import dataclass

from .exceptions import UnsupportedObserverError


@dataclass(frozen=True)
class ObserverSpec:
    observer_id: str
    privilege_level: str
    label: str
    supported_artifact_adapters: tuple[str, ...]


OBSERVER_REGISTRY = {
    "host": ObserverSpec(
        observer_id="host",
        privilege_level="host",
        label="Host observer",
        supported_artifact_adapters=("raw_report_text", "collection_manifest_v1"),
    ),
    "adb_shell": ObserverSpec(
        observer_id="adb_shell",
        privilege_level="shell",
        label="ADB shell observer",
        supported_artifact_adapters=(
            "raw_report_text",
            "adb_shell_snapshot",
            "collection_manifest_v1",
        ),
    ),
    "unprivileged_app": ObserverSpec(
        observer_id="unprivileged_app",
        privilege_level="app_sandbox",
        label="Unprivileged app observer",
        supported_artifact_adapters=("raw_report_text", "collection_manifest_v1"),
    ),
    "root_collector": ObserverSpec(
        observer_id="root_collector",
        privilege_level="root",
        label="Privileged read-only collector",
        supported_artifact_adapters=(
            "raw_report_text",
            "magisk_collector_raw",
            "collection_manifest_v1",
        ),
    ),
}

OBSERVER_PRIVILEGE = {
    observer_id: spec.privilege_level for observer_id, spec in OBSERVER_REGISTRY.items()
}


def observer_spec(observer_id: str) -> ObserverSpec:
    try:
        return OBSERVER_REGISTRY[observer_id]
    except KeyError as exc:
        supported = ", ".join(OBSERVER_REGISTRY)
        raise UnsupportedObserverError(
            f"unsupported observer {observer_id!r}; expected one of: {supported}"
        ) from exc
