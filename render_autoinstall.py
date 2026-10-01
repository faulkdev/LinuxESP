"""Render a private, per-device Ubuntu Desktop autoinstall file.

No passphrase is accepted on the command line or embedded in the repository.
The generated recovery record must be moved into an approved vault before the
installer file is distributed over a protected channel.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import stat
from pathlib import Path
from typing import Any

import yaml

_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
_USERNAME = re.compile(r"[a-z_][a-z0-9_-]{1,30}\Z")
_SHA512_HASH = re.compile(r"\$6\$[A-Za-z0-9./]{8,16}\$[A-Za-z0-9./]{86}\Z")
_YESCRYPT_HASH = re.compile(r"\$y\$[A-Za-z0-9./$]{50,}\Z")
_APPROVED_SOURCE_ID = "ubuntu-desktop"
_MARKERS = {
    "HOSTNAME": "hostname",
    "USERNAME": "username",
    "PASSWORD_HASH": "password_hash",
    "DISK_SERIAL": "disk_serial",
    "LUKS_PASSPHRASE": "luks_passphrase",
}


def _shell_single_quote(value: str) -> str:
    """Return a shell literal that cannot expand the device serial."""

    return "'" + value.replace("'", "'\"'\"'") + "'"


def _marker_count(template: str, marker: str) -> int:
    """Count one marker without treating a longer marker as its prefix."""

    pattern = rf"!device {re.escape(marker)}(?![A-Za-z0-9_])"
    return len(re.findall(pattern, template))


def _private_file(path: Path) -> None:
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode) or details.st_uid != os.getuid():
        raise ValueError("Device specification must be an owner-controlled regular file.")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise ValueError("Device specification permissions must exclude group and other access.")


def _private_directory(path: Path) -> None:
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode) or details.st_uid != os.getuid():
        raise ValueError("Output directory must be owner-controlled and not a symlink.")
    if stat.S_IMODE(details.st_mode) & 0o077:
        raise ValueError("Output directory permissions must exclude group and other access.")


def _validate_spec(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        raise TypeError("Device specification must be a JSON object.")
    required = {
        "device_id",
        "hostname",
        "username",
        "password_hash",
        "disk_serial",
    }
    if set(value) != required or any(not isinstance(value[key], str) for key in required):
        raise ValueError(
            "Device specification requires only device_id, hostname, username, "
            "disk_serial and password_hash."
        )
    if not _HOSTNAME.fullmatch(value["device_id"]) or not _HOSTNAME.fullmatch(value["hostname"]):
        raise ValueError("Device ID and hostname must be valid inventory labels.")
    disk_serial = value["disk_serial"]
    if (
        not 1 <= len(disk_serial) <= 255
        or disk_serial != disk_serial.strip()
        or not any(not character.isspace() for character in disk_serial)
        or any(ord(character) < 0x21 or ord(character) == 0x7F for character in disk_serial)
        or any(character in "*?[]" for character in disk_serial)
    ):
        raise ValueError(
            "Disk serial must be a non-empty exact udev serial without whitespace "
            "padding, control characters or glob wildcards."
        )
    if not _USERNAME.fullmatch(value["username"]) or value["username"] in {"root", "ubuntu"}:
        raise ValueError("Use a named, non-root device username.")
    password_hash = value["password_hash"]
    if not (_SHA512_HASH.fullmatch(password_hash) or _YESCRYPT_HASH.fullmatch(password_hash)):
        raise ValueError("Supply a unique salted SHA-512 or yescrypt password hash from the approved vault.")
    return value


def _create_private_file(path: Path, content: str) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def render_device_autoinstall(
    template_path: Path,
    specification_path: Path,
    output_path: Path,
    recovery_path: Path,
) -> None:
    """Write non-overwriting mode-0600 autoinstall and recovery files."""

    _private_file(specification_path)
    output_parent = output_path.parent
    if output_parent != recovery_path.parent:
        raise ValueError("Autoinstall and recovery files must share one private output directory.")
    _private_directory(output_parent)
    if output_path == recovery_path or output_path.exists() or recovery_path.exists():
        raise FileExistsError("Refusing to overwrite an existing device file.")

    spec = _validate_spec(json.loads(specification_path.read_text(encoding="utf-8")))
    passphrase = secrets.token_urlsafe(48)
    if len(passphrase) < 40 or passphrase.casefold() in {"ubuntu", "password"}:
        raise ValueError("Generated LUKS passphrase is too weak.")
    values = {**spec, "luks_passphrase": passphrase}
    template = template_path.read_text(encoding="utf-8")
    if not template.startswith("#cloud-config\n"):
        raise ValueError("Template must start with #cloud-config.")
    try:
        template_document = yaml.load(template, Loader=yaml.BaseLoader)
        source_id = template_document["autoinstall"]["source"]["id"]
    except (KeyError, TypeError, yaml.YAMLError) as error:
        raise ValueError("Template must contain an Ubuntu Desktop source id.") from error
    if source_id != _APPROVED_SOURCE_ID:
        raise ValueError(
            f"Template must pin the approved GNOME Ubuntu Desktop source id {_APPROVED_SOURCE_ID!r}."
        )
    rendered = template
    for marker, key in _MARKERS.items():
        if _marker_count(template, marker) != 1:
            raise ValueError(f"Template must contain exactly one {marker} marker.")
        rendered = re.sub(
            rf"!device {re.escape(marker)}(?![A-Za-z0-9_])",
            json.dumps(values[key]),
            rendered,
        )
    shell_token = "!device DISK_SERIAL_SHELL"
    if _marker_count(template, "DISK_SERIAL_SHELL") != 1:
        raise ValueError("Template must contain exactly one DISK_SERIAL_SHELL marker.")
    rendered = rendered.replace(shell_token, _shell_single_quote(values["disk_serial"]))
    if "!device " in rendered:
        raise ValueError("Template contains an unknown device marker.")

    recovery = json.dumps(
        {
            "device_id": spec["device_id"],
            "hostname": spec["hostname"],
            "disk_serial": spec["disk_serial"],
            "luks_passphrase": passphrase,
        },
        indent=2,
    ) + "\n"
    _create_private_file(output_path, rendered)
    try:
        _create_private_file(recovery_path, recovery)
    except BaseException:
        output_path.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--spec", required=True, type=Path, help="Mode-0600 JSON device specification")
    parser.add_argument("--output", required=True, type=Path, help="New private autoinstall YAML path")
    parser.add_argument("--recovery", required=True, type=Path, help="New private LUKS recovery JSON path")
    args = parser.parse_args()
    render_device_autoinstall(
        Path(__file__).with_name("autoinstall.template.yaml"),
        args.spec,
        args.output,
        args.recovery,
    )
    print("Rendered private Ubuntu Desktop autoinstall and recovery files. Escrow recovery before installation.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
