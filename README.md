# sdcard-check

Automatically inspects SD cards and USB storage for hardware failure when
they are plugged in, and tells three cases apart:

| Case | Typical evidence |
|---|---|
| **Failing card** | checksum failures, bad tree blocks, unreadable sectors, kernel I/O errors, read-only flag |
| **Fake capacity** | data wrapping around to low addresses, zeroed metadata high on the card, f3probe verdict |
| **External cause** (undervoltage, unsafe shutdown) | lost writes (`parent transid verify failed`), superblock generations disagreeing, undervoltage in the logs |

The automatic check is **read-only**. It never writes to the card.

## Files

| File | Installed to |
|---|---|
| `sdcard-check.sh` | `/usr/local/bin/sdcard-check.sh` |
| `sdcard-check@.service` | `/etc/systemd/system/sdcard-check@.service` |
| `sdcard-track@.service` | `/etc/systemd/system/sdcard-track@.service` |
| `99-sdcard-check.rules` | `/etc/udev/rules.d/99-sdcard-check.rules` |
| `README.md` | `/usr/local/share/doc/sdcard-check/README.md` |
| `sdcard-flasher.conf.example` | `/etc/sdcard-flasher.conf` (only if missing) |

## Install

```bash
sudo ./sdcard-check.sh --install-deps
sudo ./install.sh
```

`--install-deps` runs `apt-get install --no-install-recommends` for
btrfs-progs, e2fsprogs, dosfstools, f3, util-linux, smartmontools,
libnotify-bin and mmc-utils, then confirms every tool is on the PATH.

`install.sh` copies the files, then runs `systemctl daemon-reload` and `udevadm control --reload`.
On a Raspberry Pi, `vcgencmd` (package `libraspberrypi-bin` or `raspi-utils`)
adds the `get_throttled` check. On eMMC, `mmc-utils` is used only if the
kernel does not already expose wear data in sysfs.

Every tool is optional. If one is missing, that check is listed under
"Checks not performed" and the verdict is marked `[incomplete]`.

## Usage

Automatic: insert a card and wait for the desktop notification. To follow a check live:

```bash
journalctl -f -t sdcard-check.sh
```

In a terminal, one command that checks every card as it is inserted, asks
about the full scan when needed, and then waits for the next card:

```bash
sudo sdcard-check.sh --watch
```

While it runs, the background check steps aside (no double checks).

Manual:

```bash
sudo sdcard-check.sh sdb                 # same read-only checks as on insertion
sudo sdcard-check.sh --full sdb          # + read every sector (dd conv=noerror,sync)
sudo sdcard-check.sh --destructive sdb   # + f3probe (or badblocks -wsv): ERASES THE CARD
```

`--full` also adds `--check-data-csum` to `btrfs check`. A manual run without
`--full` whose result is WARNING or BAD asks at the end whether to run the
full read scan right away (`[y/N]`); the automatic check never asks. `--full` and
`--destructive` refuse to run from udev/systemd or without a terminal.
`--destructive` needs every partition unmounted and asks you to type
`ERASE sdb`. Just before writing, it checks that the same card is still
inserted.

**Safety:** the script finds the disk(s) holding `/` (plus `/boot*`, `/usr`,
`/var`, swap, LVM/LUKS parents, and overlay roots) at runtime and refuses to
touch them. If it cannot work out the root disk, it refuses everything.

## How to get the most complete check

Desktops automount cards as they are inserted. `btrfs check` and `e2fsck`
are skipped on mounted filesystems, because the results would be unreliable.
For a mounted btrfs you still get the superblock comparison and
`btrfs device stats`. For the full check, unmount and run it by hand:

```bash
udisksctl unmount -b /dev/sdb2
```

```bash
sudo sdcard-check.sh sdb
```

Automounting also writes to the card: the kernel replays logs, and btrfs may
create its free-space tree. If you are trying to preserve evidence from a
suspect card, disable automount before inserting it.

## Reading the output

The log is written to `/var/log/sdcard-check/<device>-<timestamp>.log`.
It has one section per check, then the summary, then the raw output of each tool.
Each finding is tagged:

- `[INFO]` normal or informational
- `[WARN]` evidence of a problem
- `[FAIL]` evidence of a failed card
- `[SKIP]` check not performed (tool missing, filesystem mounted)

The `=>` line under a finding says what it implies.

The summary ends with:

```
VERDICT: FAULTY (definite): 147 checksum errors, 2 bad tree blocks, 0 fs inconsistencies, 0 device-counter errors, 3 lost-write errors, 0 I/O errors, 0 unreadable sectors
RECOMMENDATION: The card cannot store data reliably. Replace it; do not reuse it after reflashing.
```

### Error categories

| Category | Sources | Meaning |
|---|---|---|
| checksum errors | btrfs check, kernel log, superblock csums, ext4 metadata csums | failing flash cells |
| bad tree blocks | btrfs check, kernel log | failing flash cells |
| fs inconsistencies | e2fsck / fsck.fat problems, ext4 superblock error count | real corruption |
| device counters | `btrfs device stats` (or the persistent counters when unmounted) | errors btrfs saw in use |
| lost-write errors | `parent transid verify failed`, superblock generation mismatches | power loss or unsafe shutdown |
| I/O errors | kernel log for this device, plus the Pi's own logs on the card | physical failure, or a bad reader |
| unreadable sectors | read scan, fsck read errors, SMART pending sectors, badblocks | physical failure |

Errors are de-duplicated per block address, so the same bad block reported
by the kernel and by `btrfs check` counts once. `btrfs device stats` is the
kernel's own running tally. It can include events that were also logged, so
corruption totals lean slightly high.

### Verdict rules

The corruption total is checksum errors + bad tree blocks + fs inconsistencies + device counters.

| Corruption total | Verdict |
|---|---|
| 0 | CLEAN |
| 1–9 | SUSPICIOUS: run `--full` and check the power supply before condemning the card |
| 10–99 | FAULTY (probable): back up now and plan to replace |
| ≥ 100 | FAULTY (definite): replace; do not reuse after reflashing |

| Lost writes | Verdict |
|---|---|
| 1–49 | SUSPICIOUS: suspect undervoltage or unclean shutdowns, correlated with the undervoltage counts |
| ≥ 50 | FAULTY: the card itself drops writes |

These give FAULTY regardless of counts:

- read-only flag, or CSD permanent write-protect
- any unreadable sector
- fake capacity (f3probe, or data that clearly wraps around)
- SMART FAILED
- eMMC end of life

Kernel I/O errors use `KERNEL_IO_WARN=1` and `KERNEL_IO_FAIL=10`.

### Undervoltage: where it is counted

- **This host's kernel log.** This only matters if the card was used in this
  machine, for example when the check runs on the Pi itself.
- **The card's own logs.** When a partition is mounted, or is an unmounted
  ext4 (read via `debugfs -c`, which is read-only), the script reads the Pi's
  `/var/log/kern.log`, `syslog`, and the journal. It counts undervoltage
  events and SD I/O errors the Pi recorded while running from that card.
  This is usually the useful evidence.
- **`vcgencmd get_throttled`**, when running on a Pi.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | CLEAN |
| 1 | SUSPICIOUS |
| 2 | FAULTY |
| 3 | script error or refusal |

The service treats 1 and 2 as success, so only real script errors show up in `systemctl --failed`.

## Lost-write history (across insertions)

A single check cannot see writes that a card confirmed and then silently
dropped. btrfs never overwrites live data, so losing the last commit just
rolls the filesystem back to a consistent older state, and every check
passes. To catch this:

- `sdcard-track@<dev>.service` runs while the card is inserted. Every 5 s it
  records the newest btrfs generation (or ext4 lifetime-bytes-written
  counter) this computer has written, in `/var/lib/sdcard-check/<fs-uuid>`.
- On the next insertion, the check compares what is really on the card with
  that record. For btrfs it uses the generation the kernel scanned before
  anything mounted it. If the card is behind, the filesystem went
  **backwards**. That counts as a lost-write error and gives SUSPICIOUS:
  writes were dropped on this computer, so the Pi's power supply is not the
  cause.
- Before reading an unmounted partition, the check discards Linux's cached
  copy of it (`blockdev --flushbufs`), so it reads the card itself rather
  than what Linux remembers writing. Nothing is dirty when a partition is
  unmounted, so this writes nothing.

A drop larger than `ROLLBACK_MAX` (10) btrfs generations, or an ext4 counter
falling below half its recorded value, is treated as a reflashed or different
card, and the history is reset.

History is kept per filesystem UUID and card capacity, so cards of different
sizes flashed from the same image never mix. USB readers cannot tell apart
two cards of the *same* size flashed from the same image, so a fresh one can
look like a rollback of the other. Native SD slots expose the card's unique
CID, which is added to the key, so they do not have this problem.

## Flasher station (flasher-guide.md)

The workflow from the flashing guide: several USB SD readers, each with a
number stuck on it, and an operator who just swaps cards. For every card
inserted into a numbered reader:

1. **Check:** the full read-only inspection above, including the btrfs error statistics.
   - FAULTY: **"Redukce N: VADNÁ – vyřadit"**. The card is not flashed.
   - WARNING: **"Redukce N: ZKONTROLOVAT"**. Not flashed unless `FLASH_ON_WARNING=1`.
2. **Flash:** `bmaptool copy --bmap disk.bmap disk.img.zst /dev/<card>`.
3. **Verify:** every block range in the bmap is read back from the card and
   compared with its checksum. This catches cards that accept writes and then
   lose them.
   - Success: **"Redukce N: HOTOVO"**.
   - bmaptool or the verification fails: **"Redukce N: SELHALO / VADNÁ – vyřadit"**.

Readers that are not numbered keep the normal behaviour: check, then mount.

### Setup

```bash
sudo sdcard-check.sh --install-deps     # includes bmaptool and zstd
sudo ./install.sh
# prepare the image once
bmaptool create disk.img --output disk.bmap
zstd disk.img                           # -> disk.img.zst
```

Number the readers: put a card **only** in reader 1, run the command, then
repeat for 2, 3 and 4. The number follows the USB port and slot
(`/dev/disk/by-path`), not the `sdX` name, so keep each reader in its port.

```bash
sudo sdcard-check.sh --learn 1
```

Edit `/etc/sdcard-flasher.conf`: set `FLASHER_IMAGE` and `FLASHER_BMAP`.
Try the whole flow first with `FLASHER_DRYRUN=1`, which writes nothing.

### Operator screen

```bash
sdcard-check.sh --status
```

This shows every reader with its state: prázdná / Kontrola / Flashuje NN% /
Ověřuje / HOTOVO (green) / VADNÁ, SELHALO (red) / ZKONTROLOVAT (yellow).
Desktop notifications with the reader number are sent as well.

Safety: flashing only ever happens on readers numbered in the configuration,
never on the system disk, never on a mounted card, and never if the card was
swapped during the check.

## Tuning

Edit the variables at the top of the script, or set them in
`/etc/default/sdcard-check`, which the service reads:

```
CORRUPT_WARN=1
CORRUPT_FAIL=10
CORRUPT_FATAL=100
TRANSID_WARN=1
TRANSID_FAIL=50
KERNEL_IO_WARN=1
KERNEL_IO_FAIL=10
```

## Limitations

- SD cards do not report wear. Only eMMC does.
- The read-only fake-capacity probe finds cards that wrap at a power-of-two
  size of 256 MiB or more. Only `--destructive` (f3probe) is conclusive.
- `badblocks` (the fallback when f3 is missing) cannot detect fake capacity.
- `IOSchedulingClass=idle` only has an effect with the BFQ I/O scheduler.
- If a card is swapped in a USB reader faster than the kernel polls for media
  (about 2 s), the reader may not report an empty slot in between, so no new
  check is triggered. Run the check by hand in that case.
