#!/usr/bin/env bash
# Install sdcard-check. Run as root from this directory.
set -euo pipefail
cd "$(dirname "$0")"
install -Dm755 sdcard-check.sh          /usr/local/bin/sdcard-check.sh
install -Dm644 sdcard-check@.service    /etc/systemd/system/sdcard-check@.service
install -Dm644 sdcard-track@.service    /etc/systemd/system/sdcard-track@.service
install -Dm644 99-sdcard-check.rules    /etc/udev/rules.d/99-sdcard-check.rules
install -Dm644 README.md                /usr/local/share/doc/sdcard-check/README.md
install -dm755 /var/log/sdcard-check
# Keep an existing flasher configuration (it holds the reader numbering).
[ -e /etc/sdcard-flasher.conf ] || install -Dm644 sdcard-flasher.conf.example /etc/sdcard-flasher.conf
systemctl daemon-reload
udevadm control --reload
echo "Installed. Plug in a card, then: journalctl -f -t sdcard-check.sh"
