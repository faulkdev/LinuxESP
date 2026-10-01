"""Security contract for per-device Ubuntu Desktop autoinstall rendering."""

from __future__ import annotations

import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import yaml

from render_autoinstall import render_device_autoinstall

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "autoinstall.template.yaml"


class RenderAutoinstallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.private_dir = Path(self.temp.name) / "private"
        self.private_dir.mkdir(mode=0o700)
        self.spec_path = self.private_dir / "device.json"
        self.output_path = self.private_dir / "autoinstall.yaml"
        self.recovery_path = self.private_dir / "recovery.json"
        self.spec = {
            "device_id": "asset-041",
            "hostname": "asset-041",
            "username": "enrolloperator",
            "disk_serial": "NVME-SERIAL-041",
            "password_hash": "$6$uniquesalt$" + "A" * 86,
        }
        self._write_spec(self.spec)

    def _write_spec(self, spec: dict[str, str]) -> None:
        self.spec_path.write_text(json.dumps(spec), encoding="utf-8")
        self.spec_path.chmod(0o600)

    def test_published_template_is_not_directly_installable(self) -> None:
        with self.assertRaises(yaml.constructor.ConstructorError):
            yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))

    def test_render_generates_unique_private_encrypted_install_and_recovery(self) -> None:
        with patch("render_autoinstall.secrets.token_urlsafe", return_value="aB2_" * 12):
            render_device_autoinstall(
                TEMPLATE, self.spec_path, self.output_path, self.recovery_path
            )
        document = yaml.safe_load(self.output_path.read_text(encoding="utf-8"))
        config = document["autoinstall"]
        self.assertEqual(config["storage"]["layout"]["name"], "lvm")
        self.assertEqual(
            config["storage"]["layout"]["match"]["serial"], "NVME-SERIAL-041"
        )
        self.assertEqual(config["storage"]["layout"]["password"], "aB2_" * 12)
        self.assertEqual(config["source"]["id"], "ubuntu-desktop")
        self.assertIs(config["oem"]["install"], False)
        self.assertIs(config["drivers"]["install"], False)
        preflight = config["early-commands"][0]
        self.assertIn("lsblk -dnpo NAME,TYPE", preflight)
        self.assertIn("ID_SERIAL", preflight)
        self.assertIn('[ "$matches" -ne 1 ]', preflight)
        self.assertEqual(config["identity"]["hostname"], "asset-041")
        # The approved Desktop ISO's embedded Subiquity rejects identity.groups;
        # its default identity user receives sudo access.
        self.assertNotIn("groups", config["identity"])
        self.assertIs(config["user-data"]["disable_root"], True)
        self.assertIs(config["ssh"]["install-server"], False)
        self.assertEqual(config.get("packages"), None)
        self.assertEqual(config.get("snaps"), None)
        self.assertEqual(stat.S_IMODE(self.output_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.recovery_path.stat().st_mode), 0o600)
        recovery = json.loads(self.recovery_path.read_text(encoding="utf-8"))
        self.assertEqual(recovery["device_id"], "asset-041")
        self.assertEqual(recovery["disk_serial"], "NVME-SERIAL-041")
        self.assertEqual(recovery["luks_passphrase"], "aB2_" * 12)

    def test_rejects_weak_identity_or_insecure_input_permissions(self) -> None:
        bad = dict(self.spec, username="root")
        self._write_spec(bad)
        with self.assertRaisesRegex(ValueError, "username"):
            render_device_autoinstall(
                TEMPLATE, self.spec_path, self.output_path, self.recovery_path
            )
        self._write_spec(self.spec)
        self.spec_path.chmod(0o644)
        with self.assertRaisesRegex(ValueError, "permissions"):
            render_device_autoinstall(
                TEMPLATE, self.spec_path, self.output_path, self.recovery_path
            )

    def test_requires_exact_disk_serial_without_glob_matching(self) -> None:
        for serial in ("", "  NVME-SERIAL", "NVME*", "NVME\nSERIAL"):
            self._write_spec(dict(self.spec, disk_serial=serial))
            with self.subTest(serial=serial), self.assertRaisesRegex(ValueError, "Disk serial"):
                render_device_autoinstall(
                    TEMPLATE, self.spec_path, self.output_path, self.recovery_path
                )

    def test_requires_approved_desktop_source(self) -> None:
        source = self.private_dir / "server-template.yaml"
        source.write_text(
            TEMPLATE.read_text(encoding="utf-8").replace(
                "id: ubuntu-desktop", "id: ubuntu-server"
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ValueError, "approved GNOME"):
            render_device_autoinstall(
                source, self.spec_path, self.output_path, self.recovery_path
            )

    def test_preflight_aborts_on_duplicate_serial_and_accepts_one_match(self) -> None:
        with patch("render_autoinstall.secrets.token_urlsafe", return_value="aB2_" * 12):
            render_device_autoinstall(
                TEMPLATE, self.spec_path, self.output_path, self.recovery_path
            )
        config = yaml.safe_load(self.output_path.read_text(encoding="utf-8"))["autoinstall"]
        preflight = config["early-commands"][0]
        mock_bin = self.private_dir / "bin"
        mock_bin.mkdir()
        udevadm = mock_bin / "udevadm"
        udevadm.write_text(
            "#!/bin/sh\nprintf 'ID_SERIAL=NVME-SERIAL-041\\n'\n", encoding="utf-8"
        )
        udevadm.chmod(0o700)
        lsblk = mock_bin / "lsblk"
        lsblk.write_text(
            "#!/bin/sh\nprintf '%s\\n' '/dev/sda disk' '/dev/sdb disk'\n",
            encoding="utf-8",
        )
        lsblk.chmod(0o700)
        environment = dict(os.environ, PATH=f"{mock_bin}:/usr/bin:/bin")
        duplicate = subprocess.run(
            ["bash", "-c", preflight],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertNotEqual(duplicate.returncode, 0)
        self.assertIn("found 2", duplicate.stderr)

        udevadm.write_text(
            "#!/bin/sh\ncase \"$3\" in --name=/dev/sda) printf 'ID_SERIAL=NVME-SERIAL-041\\n' ;; *) printf 'ID_SERIAL=OTHER\\n' ;; esac\n",
            encoding="utf-8",
        )
        single = subprocess.run(
            ["bash", "-c", preflight],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
        )
        self.assertEqual(single.returncode, 0, single.stderr)

    def test_preflight_shell_literal_quotes_serial(self) -> None:
        self._write_spec(dict(self.spec, disk_serial="NVME'041"))
        with patch("render_autoinstall.secrets.token_urlsafe", return_value="aB2_" * 12):
            render_device_autoinstall(
                TEMPLATE, self.spec_path, self.output_path, self.recovery_path
            )
        config = yaml.safe_load(self.output_path.read_text(encoding="utf-8"))["autoinstall"]
        preflight = config["early-commands"][0]
        self.assertIn("expected_serial='NVME'\"'\"'041'", preflight)
        syntax = subprocess.run(
            ["bash", "-n"],
            input=preflight,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(syntax.returncode, 0, syntax.stderr)

    def test_never_overwrites_an_existing_install_file(self) -> None:
        self.output_path.write_text("existing", encoding="utf-8")
        with self.assertRaises(FileExistsError):
            render_device_autoinstall(
                TEMPLATE, self.spec_path, self.output_path, self.recovery_path
            )
        self.assertEqual(self.output_path.read_text(encoding="utf-8"), "existing")
        self.assertFalse(self.recovery_path.exists())

    def test_rejects_world_readable_output_directory(self) -> None:
        self.private_dir.chmod(0o755)
        with self.assertRaisesRegex(ValueError, "directory"):
            render_device_autoinstall(
                TEMPLATE, self.spec_path, self.output_path, self.recovery_path
            )

    def test_secret_generator_must_return_strong_value(self) -> None:
        with (
            patch("render_autoinstall.secrets.token_urlsafe", return_value="ubuntu"),
            self.assertRaisesRegex(ValueError, "passphrase"),
        ):
            render_device_autoinstall(
                TEMPLATE, self.spec_path, self.output_path, self.recovery_path
            )
        self.assertFalse(self.output_path.exists())
        self.assertFalse(self.recovery_path.exists())


if __name__ == "__main__":
    unittest.main()
