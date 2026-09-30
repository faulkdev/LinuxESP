"""Security contract for per-device Ubuntu Desktop autoinstall rendering."""

from __future__ import annotations

import json
import stat
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
        self.assertEqual(config["storage"]["layout"]["password"], "aB2_" * 12)
        self.assertEqual(config["identity"]["hostname"], "asset-041")
        self.assertEqual(config["identity"]["groups"]["override"], ["sudo"])
        self.assertIs(config["user-data"]["disable_root"], True)
        self.assertIs(config["ssh"]["install-server"], False)
        self.assertEqual(config.get("packages"), None)
        self.assertEqual(config.get("snaps"), None)
        self.assertEqual(stat.S_IMODE(self.output_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.recovery_path.stat().st_mode), 0o600)
        recovery = json.loads(self.recovery_path.read_text(encoding="utf-8"))
        self.assertEqual(recovery["device_id"], "asset-041")
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
