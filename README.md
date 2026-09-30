# LinuxESP: private Ubuntu Desktop installation for managed devices

This repository contains a **per-device** Ubuntu Desktop autoinstall template. The
published template is intentionally not installable. `render_autoinstall.py`
generates a unique LUKS recovery passphrase and writes both the installation
configuration and recovery record to owner-only files. No Intune or Defender
tenant package, shared disk secret, or example application is embedded.
The former public `autoinstall.yaml` URL is retired; use the renderer for each
device.

The installer prepares an encrypted workstation. An operator must complete
Intune enrollment, Defender onboarding, policy assignment, and evidence checks
after installation. The generated file itself does not establish compliance.

## Requirements

- Ubuntu Desktop 24.04 LTS x86-64 with GNOME and supported hardware. Check
  [current Intune Linux requirements](https://learn.microsoft.com/en-us/intune/device-enrollment/guide-linux)
  before approving another release. Ubuntu Server is not a substitute for the
  managed Desktop lane.
- A protected device inventory entry, a unique salted local password hash from
  the approved credential vault, and an approved location for the LUKS recovery
  record. The local account has the `sudo` group for installation operations;
  root login and SSH server installation are disabled.
- A private output directory owned by the operator with mode `0700`.
- A protected delivery channel for the rendered configuration. Never host it at
  a public or long-lived raw URL: autoinstall's LUKS password is present in the
  file by design. Revoke the delivery URL and remove local copies after use;
  retain the recovery secret only in the approved vault.

[Canonical documents](https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html#storage)
that an `lvm` layout with a password enables LUKS encryption. Its
[identity section](https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html#identity)
requires an encrypted password hash. The required tags in the committed
template make direct use fail before a fixed secret can become an installation
default.

## Render one device

Create a mode-`0600` JSON specification in a mode-`0700` directory:

```json
{
  "device_id": "asset-041",
  "hostname": "asset-041",
  "username": "enrolloperator",
  "disk_serial": "NVME-SERIAL-041",
  "password_hash": "<unique salted SHA-512 or yescrypt hash from your vault>"
}
```

The example hash text above is intentionally invalid. Supply a real,
device-specific hash; do not place a plaintext account password in this file.
Render from the repository root:

```bash
python3 render_autoinstall.py \
  --spec /private/device.json \
  --output /private/autoinstall.yaml \
  --recovery /private/recovery.json
```

The command refuses weak/invalid input, group-readable files and directories,
unknown template markers, wildcard disk serials, an unapproved source ID, and
existing outputs. The disk serial is rendered as an exact match so an
unrelated largest disk cannot be selected. An installer-side preflight
enumerates whole disks and aborts unless exactly one reports that `ID_SERIAL`,
which also rejects duplicate serials. It prints no secrets. Escrow
`recovery.json` before releasing the installation file. Treat the rendered YAML
as a secret and use a distinct specification and render operation per device.

The committed template pins `source.id: ubuntu-desktop`, the standard GNOME
Ubuntu Desktop source. Before each release, verify that the approved Ubuntu
Desktop ISO's `casper/install-sources.yaml` contains this ID. Canonical documents
that source IDs are ISO-specific and that the ISO is the authoritative place to
confirm them. A minimal Desktop source must be approved as a separate template
change and validated against the target ISO; it is not silently substituted.

The `disk_serial` value must be copied from the target device's hardware
inventory or installer environment. Confirm the serial against the physical
device before starting installation. Canonical's schema validator cannot prove
that a serial matches a particular machine.

## Validate and install

1. Run `python3 -m unittest discover -s tests -v` after installing
   `requirements-dev.txt` into a local virtual environment.
2. Treat the rendered structure and the target ISO as separate validation
   gates. The repository tests validate the pinned `source.id`, the encrypted
   LVM match, and the duplicate-serial preflight. Canonical's standalone
   [`validate-autoinstall-user-data.py`](https://canonical-subiquity.readthedocs-hosted.com/en/latest/howto/autoinstall-validation.html)
   assumes an Ubuntu Server target and `synthesized` source; it may reject the
   valid `ubuntu-desktop` source before checking the Desktop configuration.
   Run it when its documented dependencies are available and retain its output,
   but do not treat that server-oriented result as the Desktop ISO gate.
   Before installation, verify that the approved ISO's
   `casper/install-sources.yaml` contains `ubuntu-desktop`, that the rendered
   source ID matches it, and that the target device has exactly one matching
   `ID_SERIAL`. Canonical states that schema validation cannot prove media or
   disk selection for a particular machine.
3. Perform a clean Ubuntu Desktop 24.04 installation in a VM with a disposable
   test specification before adopting a changed template. Verify GNOME login,
   a disabled root login, no SSH server, encrypted LVM, and recovery-key unlock.
   Repeat on representative physical hardware; the VM test alone cannot prove
   disk matching or device support. `oem.install: false` and
   `drivers.install: false` are explicit baseline choices; hardware requiring a
   driver needs a separately reviewed, signed package decision.
4. Deliver each rendered file through an authenticated, expiring endpoint or
   protected removable media. Confirm the selected target disk before install.
   Revoke the endpoint afterward and record installation and recovery escrow
   evidence.

The template does not add third-party APT repositories. This avoids the
unscoped `trusted.gpg.d` key and unpinned package installation from the earlier
example. Install Intune and Defender using their current vendor-supported
instructions after the device boots.

## Operator onboarding to Intune and Defender

1. Verify corporate ownership, Ubuntu Desktop/GNOME version, encryption,
   approved outbound connectivity, Intune and Defender licenses, and the
   required assignments for this physical-device lane.
2. Install Microsoft Intune Portal and Microsoft Edge using the current
   [Microsoft Linux app procedure](https://learn.microsoft.com/en-us/intune/user-help/company-portal/intune-app-linux).
   Use a repository key scoped with `signed-by`; do not add it to global
   `trusted.gpg.d`. Record package versions and repository fingerprints.
3. Have the named user sign in to the Intune app and complete
   [Linux enrollment](https://learn.microsoft.com/en-us/intune/user-help/enrollment/enroll-linux).
   Record the Entra/Intune device IDs and verify device ownership, check-in,
   compliance, encryption, and assignments in the tenant. Enrollment is a
   user action; it is not completed by this autoinstall file.
4. Download the **tenant-specific** Defender deployment tool from that tenant's
   Defender portal. Run the vendor tool's `--pre-req` and
   `--connectivity-test` checks, correct failures, then run the tool to install
   and onboard. Follow the current
   [Microsoft deployment-tool procedure](https://learn.microsoft.com/en-us/defender-endpoint/linux-install-with-defender-deployment-tool).
   Never commit or reuse the package across tenants.
5. Verify `mdatp health`, the expected tenant `org_id`, real-time protection,
   signature freshness, scan schedule, and the device in Defender inventory.
   Test a detection with an approved harmless method and preserve the result.
   A weekly malware-scan policy and hardening/compliance modules must be
   assigned separately; this installer does not claim those controls.

Review [NATTOMR's Linux hardening modules](https://github.com/NATTOMR/Linux-Server-Hardening-Secure-Configuration.)
as pattern material for maintained workstation hardening. Do not execute or
vendor those server modules unchanged: their platform assumptions and dry-run
behavior require separate review and tests for Ubuntu Desktop.

## Sources

- [Canonical autoinstall reference](https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html)
- [Canonical pre-install validation](https://canonical-subiquity.readthedocs-hosted.com/en/latest/howto/autoinstall-validation.html)
- [Microsoft Intune Linux enrollment](https://learn.microsoft.com/en-us/intune/device-enrollment/guide-linux)
- [Microsoft Defender Linux deployment tool](https://learn.microsoft.com/en-us/defender-endpoint/linux-install-with-defender-deployment-tool)
