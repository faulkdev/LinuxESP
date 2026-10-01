# Ubuntu Desktop autoinstall VM validation

Validation date: 2026-10-01 UTC. This record concerns a disposable local VM;
no Intune or Defender tenant was contacted.

| Item | Observed result |
| --- | --- |
| Installation media | Official Ubuntu 24.04.4 Desktop AMD64 ISO from `releases.ubuntu.com/24.04` |
| ISO SHA-256 | `3a4c9877b483ab46d7c3fbe165a0db275e1ae3cfe56a5657e5a47c2f99a99d1e`, matching Ubuntu's published `SHA256SUMS` |
| Desktop source | ISO `casper/install-sources.yaml` lists `ubuntu-desktop`; the rendered file selected that ID |
| Test disk | Disposable 64 GiB QEMU virtio disk with an exact `ID_SERIAL` match to the private specification |
| Installation | Subiquity/curtin completed and requested reboot; QEMU exited normally |
| Encryption | Installer reported a LUKS partition with LVM and an ext4 target; the installed disk required the generated per-device recovery passphrase at boot |
| Boot | The escrowed passphrase unlocked the disk and the installed GNOME login screen appeared |
| Installed-system inspection | A live ISO unlocked the disk again for read-only inspection. Root's shadow entry is locked, `enrolloperator` belongs to `sudo`, `gnome-shell` is installed, and neither the `openssh-server` package nor an `sshd` binary is present. |

The installer correctly stopped when a deliberately mismatched disk serial was
present. An earlier test also exposed `identity.groups` incompatibility in the
24.04.4 Desktop Subiquity build; the committed template omits that field and
uses the Desktop installer's default local-account sudo behavior. The final
rendered file installed successfully. Unit tests cover unique secret creation,
exact disk selection, output permissions, prohibited example packages and
third-party repositories, and the template's root/SSH settings.

The standalone Canonical user-data validator depends on Subiquity packages
that were not installed on the host and assumes the Server installation source.
The actual Desktop ISO's installer validated the schema and media-specific
source during this VM run. Retain that ISO check for every media update.

This test does not demonstrate physical-device disk identity, corporate
enrollment, Defender onboarding, effective hardening policy, or tenant
compliance. Those are separate deployment and operator evidence gates in the
[README](README.md). The generated installation file, password hash, and LUKS
recovery record stayed in private temporary test storage and are not in git.

Sources: [Ubuntu release checksums](https://releases.ubuntu.com/24.04/SHA256SUMS),
[Canonical autoinstall reference](https://canonical-subiquity.readthedocs-hosted.com/en/latest/reference/autoinstall-reference.html),
and [Canonical validation guidance](https://canonical-subiquity.readthedocs-hosted.com/en/latest/howto/autoinstall-validation.html).
