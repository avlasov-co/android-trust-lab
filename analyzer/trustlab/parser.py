"""Parsers for raw Android Trust Lab artifacts."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Any

SECTION_RE = re.compile(r"^===\s*([A-Z0-9_ -]+)\s*===\s*$")
GETPROP_RE = re.compile(r"^\[([^\]]+)\]:\s*\[(.*)\]\s*$")
ID_RE = re.compile(r"uid=(\d+)\(([^)]*)\)\s+gid=(\d+)\(([^)]*)\)")


def split_sections(text: str) -> Dict[str, str]:
    sections: Dict[str, List[str]] = {"UNSECTIONED": []}
    current = "UNSECTIONED"
    for line in text.splitlines():
        match = SECTION_RE.match(line.strip())
        if match:
            current = match.group(1).strip().upper().replace(" ", "_")
            sections.setdefault(current, [])
        else:
            sections.setdefault(current, []).append(line)
    return {key: "\n".join(value).strip() for key, value in sections.items() if "\n".join(value).strip()}


def parse_getprop(text: str) -> Dict[str, str]:
    props: Dict[str, str] = {}
    for line in text.splitlines():
        match = GETPROP_RE.match(line.strip())
        if match:
            props[match.group(1)] = match.group(2)
    return props



def parse_key_values(text: str) -> Dict[str, str]:
    values: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def parse_id(text: str) -> Dict[str, str]:
    match = ID_RE.search(text.strip())
    if not match:
        return {"uid": "unknown", "user": "unknown", "gid": "unknown", "group": "unknown", "raw": text.strip()}
    return {
        "uid": match.group(1),
        "user": match.group(2),
        "gid": match.group(3),
        "group": match.group(4),
        "raw": text.strip(),
    }


def parse_getenforce(text: str) -> str:
    value = text.strip().lower()
    if value in {"enforcing", "permissive", "disabled"}:
        return value
    if "permission denied" in value:
        return "inaccessible"
    return "unknown"


def parse_mount_line(line: str) -> Dict[str, Any]:
    raw = line.strip()
    if not raw:
        return {"raw": raw, "mount_point": "unknown", "fs_type": "unknown", "options": [], "classification": "unknown"}

    mount_point = "unknown"
    fs_type = "unknown"
    options: List[str] = []

    # Common Android/Linux format: device on /path type ext4 (ro,seclabel,...)
    m = re.search(r"\s+on\s+(\S+)\s+type\s+(\S+)\s+\(([^)]*)\)", raw)
    if m:
        mount_point = m.group(1)
        fs_type = m.group(2)
        options = [part.strip() for part in m.group(3).split(",") if part.strip()]
    else:
        # /proc/mounts style: device mountpoint fstype opts ...
        parts = raw.split()
        if len(parts) >= 4:
            mount_point = parts[1]
            fs_type = parts[2]
            options = [part.strip() for part in parts[3].split(",") if part.strip()]

    classification = classify_mount(fs_type, options)
    return {
        "raw": raw,
        "mount_point": mount_point,
        "fs_type": fs_type,
        "options": options,
        "classification": classification,
    }


def classify_mount(fs_type: str, options: List[str]) -> str:
    opts = set(options)
    if fs_type == "overlay":
        return "overlay"
    if fs_type == "tmpfs":
        return "tmpfs"
    if "bind" in opts or "rbind" in opts:
        return "bind mount"
    if "rw" in opts:
        return "read-write"
    if "ro" in opts:
        return "read-only"
    return "unknown"


def parse_mounts(text: str) -> List[Dict[str, Any]]:
    return [parse_mount_line(line) for line in text.splitlines() if line.strip()]


def parse_paths(text: str) -> List[str]:
    values = []
    for line in text.splitlines():
        line = line.strip()
        if line and not line.lower().startswith("not found"):
            values.append(line)
    return values


def parse_processes(text: str) -> Dict[str, Any]:
    lines = [line for line in text.splitlines() if line.strip()]
    joined = "\n".join(lines).lower()
    return {
        "raw_line_count": len(lines),
        "init_visible": " init" in joined or "\ninit" in joined,
        "adbd_visible": "adbd" in joined,
        "zygote_visible": "zygote" in joined,
        "system_server_visible": "system_server" in joined,
        "magisk_processes_visible": "magisk" in joined,
        "process_contexts_available": "u:r:" in joined,
    }


def parse_raw_report(path: str | Path) -> Dict[str, Any]:
    text = Path(path).read_text(encoding="utf-8")
    sections = split_sections(text)
    return {
        "sections": sections,
        "properties": parse_getprop(sections.get("GETPROP", "") or sections.get("PROPS", "")),
        "boot_state_raw": parse_key_values(sections.get("BOOT_STATE", "")),
        "mounts": parse_mounts(sections.get("MOUNT", "") or sections.get("MOUNTS", "")),
        "id": parse_id(sections.get("ID", "")),
        "selinux_mode": parse_getenforce(sections.get("GETENFORCE", "") or sections.get("SELINUX", "")),
        "cmdline": sections.get("CMDLINE", ""),
        "su_paths": parse_paths(sections.get("SU_PATHS", "")),
        "magisk": sections.get("MAGISK", ""),
        "processes": parse_processes(sections.get("PS", "") or sections.get("PROCESSES", "")),
    }
