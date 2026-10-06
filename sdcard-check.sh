#!/usr/bin/env bash
# sdcard-check.sh - read-only health inspection of SD cards and USB storage.
#
# Usage:
#   sdcard-check.sh [--full] [--destructive] [--no-notify] [--no-unmount] [DEVICE]
#     (without DEVICE: the one SD card / USB disk that is inserted)
#   sdcard-check.sh --udev DEVICE             (what sdcard-check@.service runs)
#   sdcard-check.sh --check-eligible DEVICE   (ExecCondition helper; exit 0 = check it)
#   sdcard-check.sh --install-deps            (apt: install every tool this script uses)
#   sdcard-check.sh --track DEVICE            (what sdcard-track@.service runs)
#   sdcard-check.sh --learn N [DEVICE]        (flasher: this card's reader is number N)
#   sdcard-check.sh --status                  (flasher: operator screen for all readers)
#   sdcard-check.sh --watch                   (terminal: check every card as it is inserted)
#
# DEVICE is a whole disk: sdb, /dev/sdb, mmcblk0, /dev/disk/by-id/...
#
# Exit codes: 0 CLEAN, 1 SUSPICIOUS (warnings), 2 FAULTY (errors),
#             3 script error or refusal.

set -uo pipefail

# ---------------------------------------------------------------------------
# Thresholds. Edit here, or override from the environment
# (the systemd unit reads /etc/default/sdcard-check).
#
# Corruption tiers apply to: checksum failures + bad tree blocks +
# filesystem inconsistencies + btrfs device error counters.
CORRUPT_WARN=${CORRUPT_WARN:-1}       # >= this -> SUSPICIOUS
CORRUPT_FAIL=${CORRUPT_FAIL:-10}      # >= this -> FAULTY (probable)
CORRUPT_FATAL=${CORRUPT_FATAL:-100}   # >= this -> FAULTY (definite)
# Lost-write tiers apply to: parent transid failures + superblock
# generation mismatches.
TRANSID_WARN=${TRANSID_WARN:-1}       # >= this -> SUSPICIOUS (power / unsafe shutdown)
TRANSID_FAIL=${TRANSID_FAIL:-50}      # >= this -> FAULTY (card drops writes)
# Kernel-logged I/O errors for this device since it was attached.
KERNEL_IO_WARN=${KERNEL_IO_WARN:-1}
KERNEL_IO_FAIL=${KERNEL_IO_FAIL:-10}

LOG_DIR=${LOG_DIR:-/var/log/sdcard-check}
# Generation history: lets a later insertion see writes the card lost.
STATE_DIR=${STATE_DIR:-/var/lib/sdcard-check}
ROLLBACK_MAX=${ROLLBACK_MAX:-10}         # btrfs drops larger than this = reflashed/other card
TRACK_INTERVAL=${TRACK_INTERVAL:-5}      # seconds between samples in --track mode
# Desktop automounts (/run/media, /media) are unmounted for the check and
# mounted back afterwards. In udev mode the udev rule holds the automount,
# and the card is mounted for the logged-in user once the check is done.
AUTO_UNMOUNT=${AUTO_UNMOUNT:-1}
AUTOMOUNT_AFTER=${AUTOMOUNT_AFTER:-1}
AUTOMOUNT_EXT=${AUTOMOUNT_EXT:-0}        # Ubuntu does not automount ext4 either

# Flasher station (see /etc/sdcard-flasher.conf): cards in numbered readers
# are checked, then flashed with bmaptool if they pass, then verified.
FLASHER_CONF=${FLASHER_CONF:-/etc/sdcard-flasher.conf}
FLASHER_IMAGE=""          # e.g. /srv/flasher/disk.img.zstd; empty = flasher off
FLASHER_BMAP=""           # e.g. /srv/flasher/disk.bmap
FLASH_ON_WARNING=0        # 1 = also flash SUSPICIOUS cards
FLASHER_VERIFY=1          # read the card back and compare with the bmap checksums
FLASHER_DRYRUN=0          # 1 = do everything except writing (for testing)
FLASH_STATE_DIR=${FLASH_STATE_DIR:-/run/sdcard-flasher}
# While "--watch" runs in a terminal, the background (udev) check steps aside.
WATCH_PIDFILE=/run/sdcard-check-watch.pid
# shellcheck source=/dev/null
[[ -r $FLASHER_CONF ]] && source "$FLASHER_CONF"
FULL_CHUNK_MB=${FULL_CHUNK_MB:-64}        # --full reads in chunks of this size
FULL_MAX_RESCAN=${FULL_MAX_RESCAN:-16}    # bad chunks re-read at 4 KiB to count sectors
FAKE_SAMPLES=${FAKE_SAMPLES:-16}          # read-only fake-capacity probe sample count
FAKE_MIN_REAL_MB=${FAKE_MIN_REAL_MB:-256} # smallest real capacity tried for wrap-around
# ---------------------------------------------------------------------------

PROG=sdcard-check
MODE_TRACK=0
DEV="" SYS="" MODE_FULL=0 MODE_DESTRUCTIVE=0 MODE_UDEV=0 MODE_ELIGIBLE=0 NOTIFY=1
WORK="" LOGFILE="" DONE=0 RAWN=0 RAWF="" FINGERPRINT=""
LEVEL=0                      # highest level raised directly by a finding
declare -a FINDINGS=() SKIPPED=() RAW_FILES=()
declare -A CSUM_KEYS=() BADTREE_KEYS=() TRANSID_KEYS=() KDEVSTATS=()
N_FSINCON=0 N_DEVCNT=0 N_SUPERGEN=0 N_BTRFS_OTHER=0
N_KIO=0 N_KTIMEOUT=0 N_KRESET=0 N_CARD_IO=0 N_UNREADABLE=0
N_UV_HOST=0 N_UV_CARD=0 N_UNCLEAN=0 N_ZEROED=0 N_WRAPPED=0
THROTTLED="n/a" FLAG_RO=0 FLAG_FAKE=0 FULL_DONE=0 SIZE_BYTES=0 LBS=512
TRANSPORT="" MMC_TYPE="" MODEL=""
# GNU dd: Ubuntu 25.10+ ships uutils as "dd", which rejects some reads with
# EINVAL and words errors differently; GNU dd is still there as "gnudd".
DD=dd; command -v gnudd >/dev/null 2>&1 && DD=gnudd
DDIN=(iflag=direct)          # dropped if the device rejects O_DIRECT
RE_MEDIA_ERR='Input/output error|I/O error'
TOOL_ERRS=0                  # read failures that were not media errors
N_ROLLBACK=0                 # commits lost since this host last wrote the card
N_UNSTABLE=0                 # blocks that read back differently on repeated reads
declare -A CSUM_FOUND=()     # block -> distinct checksums seen when re-reading it
KSTART=1                     # kernel log line where this medium was attached
declare -a REMOUNT=()        # "partition user" pairs this run unmounted
declare -a MOUNTED_MSGS=()
READER="" FLASHER=0 FLASH_RESULT="" FLASH_FP="" VERIFY_BAD=0

# ---------------------------------------------------------------- helpers ---
have()    { command -v "$1" >/dev/null 2>&1; }
section() { printf '\n== %s ==\n' "$*"; }
kv()      { printf '  %-24s %s\n' "$1" "$2"; }
note()    { printf '  - %s\n' "$*"; }
human()   { numfmt --to=iec-i --suffix=B --format=%.1f "$1" 2>/dev/null || echo "$1 bytes"; }
trim()    { local s=$*; s=${s#"${s%%[![:space:]]*}"}; printf '%s' "${s%"${s##*[![:space:]]}"}"; }
readf()   { [[ -r $1 ]] && trim "$(<"$1")"; }
add_key() { local -n _set=$1; _set["$2"]=1; }

# finding LEVEL WHAT [IMPLICATION]  - prints and raises the verdict floor.
finding() {
    local lvl=$1 what=$2 why=${3:-} tag
    case $lvl in 0) tag=INFO ;; 1) tag=WARN ;; *) tag=FAIL ;; esac
    printf '  [%s] %s\n' "$tag" "$what"
    [[ -n $why ]] && printf '         => %s\n' "$why"
    (( lvl > 0 )) && FINDINGS+=("[$tag] $what")
    (( lvl > LEVEL )) && LEVEL=$lvl
}
# observe TAG WHAT [IMPLICATION] - prints only; counts decide the verdict.
observe() {
    printf '  [%s] %s\n' "$1" "$2"
    [[ -n ${3:-} ]] && printf '         => %s\n' "$3"
    [[ $1 != INFO ]] && FINDINGS+=("[$1] $2")
}
skip_check() { SKIPPED+=("$1"); printf '  [SKIP] %s\n' "$1"; }
die()        { printf '%s: ERROR: %s\n' "$PROG" "$*" >&2; DONE=1; exit 3; }
# rawfile NAME: sets RAWF to a new file for a tool's raw output. Not used
# via $(...), which would lose the RAW_FILES entry in a subshell.
rawfile()    { RAWN=$((RAWN + 1)); RAWF=$(printf '%s/raw-%02d-%s.txt' "$WORK" "$RAWN" "$1"); RAW_FILES+=("$RAWF"); }

usage() {
    sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

# ------------------------------------------------------- device resolution ---
resolve_dev() {
    local arg=$1 path name
    path=$(readlink -f -- "$( [[ $arg == /* ]] && echo "$arg" || echo "/dev/$arg")") || true
    name=${path##*/}
    [[ -n $name && -e /sys/class/block/$name ]] || { echo "no such block device: $arg" >&2; return 1; }
    if [[ -e /sys/class/block/$name/partition ]]; then
        local parent; parent=$(basename "$(dirname "$(readlink -f "/sys/class/block/$name")")")
        echo "$arg is a partition; pass the whole disk ($parent)" >&2; return 1
    fi
    [[ -d /sys/block/$name ]] || { echo "$arg is not a whole disk" >&2; return 1; }
    case $name in dm-*|md*|zram*|ram*|sr*|nbd*) echo "$name is not a storage device this tool inspects" >&2; return 1 ;; esac
    printf '%s' "$name"
}

# Whole disks that hold /, /boot, /usr, /var or active swap. Fails (non-zero)
# if the root disk cannot be determined, so callers refuse rather than guess.
disks_of() {
    local src=$1 out
    if [[ $src != /dev/* ]]; then return 1; fi
    out=$(lsblk -nsro NAME,TYPE "$src" 2>/dev/null | awk '$2=="disk"{print $1}' | sort -u)
    [[ -n $out ]] || return 1
    printf '%s\n' "$out"
}
system_disks() {
    local mp src fstype uuid d opt dir
    local -a srcs=()
    for mp in / /boot /boot/efi /boot/firmware /usr /var; do
        src=$(findmnt -nvo SOURCE --mountpoint "$mp" 2>/dev/null | head -1)
        [[ -z $src ]] && { [[ $mp == / ]] && return 1; continue; }
        fstype=$(findmnt -no FSTYPE --mountpoint "$mp" | head -1)
        if [[ $fstype == overlay ]]; then
            # Overlay root (e.g. Raspberry Pi OS overlay mode): follow lower/upper dirs.
            for opt in $(findmnt -no OPTIONS --mountpoint "$mp" | tr ',' ' '); do
                case $opt in lowerdir=*|upperdir=*)
                    for dir in $(tr ':' ' ' <<<"${opt#*=}"); do
                        srcs+=("$(findmnt -nvo SOURCE -T "$dir" | head -1)")
                    done ;;
                esac
            done
        elif [[ $src != /dev/* ]]; then
            # Not a block path (zfs, nfs, ...): try the device number.
            local mm; mm=$(stat -c '%Hd:%Ld' "$mp" 2>/dev/null)
            if [[ -e /sys/dev/block/$mm ]]; then
                srcs+=("/dev/$(basename "$(readlink -f "/sys/dev/block/$mm")")")
            elif [[ $mp == / ]]; then
                return 1
            fi
        else
            srcs+=("$src")
        fi
        if [[ $fstype == btrfs ]]; then
            uuid=$(findmnt -no UUID --mountpoint "$mp" | head -1)
            for d in /sys/fs/btrfs/"$uuid"/devices/*; do [[ -e $d ]] && srcs+=("/dev/${d##*/}"); done
        fi
    done
    while read -r d _; do [[ $d == /dev/* ]] && srcs+=("$d"); done < <(tail -n +2 /proc/swaps)

    local found=0 s
    for s in "${srcs[@]}"; do
        [[ -n $s ]] || continue
        if disks_of "$s"; then found=1; fi
    done
    (( found )) || return 1
}
refuse_if_system_disk() {
    local sysd
    sysd=$(system_disks | sort -u) || { echo "cannot determine which disk holds /; refusing to operate" >&2; return 1; }
    [[ -n $sysd ]] || { echo "cannot determine which disk holds /; refusing to operate" >&2; return 1; }
    if grep -qx -- "$DEV" <<<"$sysd"; then
        echo "/dev/$DEV holds the running system (/, /boot, /usr, /var or swap); refusing to operate" >&2
        return 1
    fi
}

# ------------------------------------------------------------ device facts ---
device_facts() {
    section "Device"
    SIZE_BYTES=$(( $(<"$SYS/size") * 512 ))
    (( SIZE_BYTES > 0 )) || die "/dev/$DEV has no medium (size 0)"
    LBS=$(readf "$SYS/queue/logical_block_size"); LBS=${LBS:-512}
    TRANSPORT=$(lsblk -dno TRAN "/dev/$DEV" 2>/dev/null | tr -d ' ')
    [[ $DEV == mmcblk* ]] && TRANSPORT=${TRANSPORT:-mmc}
    [[ $DEV == mmcblk* ]] && MMC_TYPE=$(readf "$SYS/device/type")
    local vendor model
    vendor=$(readf "$SYS/device/vendor"); model=$(readf "$SYS/device/model")
    [[ -z $model ]] && model=$(readf "$SYS/device/name")
    MODEL=$(trim "$vendor $model"); MODEL=${MODEL:-unknown}

    kv "Device" "/dev/$DEV"
    kv "Model" "$MODEL"
    kv "Size" "$(human "$SIZE_BYTES") ($SIZE_BYTES bytes, ${LBS}-byte sectors)"
    kv "Transport" "${TRANSPORT:-unknown}${MMC_TYPE:+ ($MMC_TYPE card)}"
    kv "Removable" "$(readf "$SYS/removable")"
    kv "Read-only flag" "$(readf "$SYS/ro")  (/sys/block/$DEV/ro)"
    if [[ $DEV == mmcblk* ]]; then
        local f
        for f in manfid oemid name date serial; do
            [[ -r $SYS/device/$f ]] && kv "Card $f" "$(readf "$SYS/device/$f")"
        done
    fi
    note "Partitions:"
    lsblk -o NAME,SIZE,FSTYPE,LABEL,MOUNTPOINTS "/dev/$DEV" 2>/dev/null | sed 's/^/      /'
}

write_protect_checks() {
    section "Write protection"
    if [[ $(readf "$SYS/ro") == 1 ]]; then
        FLAG_RO=1
        finding 2 "Kernel reports the device read-only (/sys/block/$DEV/ro = 1)" \
            "Flash cards lock themselves read-only when they run out of spare blocks; a card in that state is dead. First rule out the lock slider on the SD card/adapter."
    else
        finding 0 "Device is writable (ro = 0)"
    fi
    # Native SD/MMC slot: the card's own write-protect bits live in its CSD register.
    local csd; csd=$(readf "$SYS/device/csd")
    if [[ -n $csd && ${#csd} -ge 4 ]]; then
        local low=$(( 16#${csd: -4} ))
        if (( (low >> 13) & 1 )); then
            FLAG_RO=1
            finding 2 "Card has PERM_WRITE_PROTECT set in its CSD register" "The card's controller has permanently locked it: end of life."
        elif (( (low >> 12) & 1 )); then
            finding 1 "Card has TMP_WRITE_PROTECT set in its CSD register" "Temporarily write-protected by a host command; unusual, and may be the controller giving up."
        else
            finding 0 "CSD write-protect bits clear"
        fi
    fi
}

emmc_health() {
    [[ $DEV == mmcblk* ]] || return 0
    section "Wear (eMMC)"
    if [[ $MMC_TYPE != MMC ]]; then
        note "This is an ${MMC_TYPE:-SD} card. SD cards do not report wear (only eMMC has EXT_CSD); wear is judged from the errors below."
        return 0
    fi
    local lt pe a b
    lt=$(readf "$SYS/device/life_time"); pe=$(readf "$SYS/device/pre_eol_info")
    if [[ -z $lt || -z $pe ]]; then
        if have mmc; then
            local f; rawfile mmc-extcsd; f=$RAWF
            mmc extcsd read "/dev/$DEV" >"$f" 2>&1
            a=$(sed -n 's/.*LIFE_TIME_EST_TYP_A\]: *\(0x[0-9a-fA-F]*\).*/\1/p' "$f" | head -1)
            b=$(sed -n 's/.*LIFE_TIME_EST_TYP_B\]: *\(0x[0-9a-fA-F]*\).*/\1/p' "$f" | head -1)
            pe=$(sed -n 's/.*PRE_EOL_INFO\]: *\(0x[0-9a-fA-F]*\).*/\1/p' "$f" | head -1)
            lt="$a $b"
        else
            skip_check "eMMC wear: no sysfs life_time and mmc-utils not installed"
            return 0
        fi
    fi
    read -r a b <<<"$lt"
    local worst=$(( ${a:-0} > ${b:-0} ? ${a:-0} : ${b:-0} ))
    kv "Life time estimate" "A=$a B=$b (0x01 = 0-10% used ... 0x0A = 90-100%, 0x0B = exceeded)"
    kv "Pre-EOL info" "$pe (0x01 normal, 0x02 warning, 0x03 urgent)"
    case $(( pe )) in
        3) finding 2 "eMMC reports PRE_EOL urgent" "Reserved blocks are nearly exhausted; the device is at end of life." ;;
        2) finding 1 "eMMC reports PRE_EOL warning" "80% of reserved blocks consumed; plan replacement." ;;
    esac
    if (( worst >= 11 )); then
        finding 2 "eMMC has exceeded its rated write endurance" "Failures are expected; replace it."
    elif (( worst >= 9 )); then
        finding 1 "eMMC has used $(( (worst - 1) * 10 ))-$(( worst * 10 ))% of its rated life" "Approaching end of life."
    elif (( worst >= 1 )); then
        finding 0 "eMMC wear $(( (worst - 1) * 10 ))-$(( worst * 10 ))% of rated life"
    fi
}

smart_health() {
    [[ $DEV == mmcblk* || $DEV == loop* ]] && return 0
    section "SMART"
    have smartctl || { skip_check "SMART: smartctl (smartmontools) not installed"; return 0; }
    local f rc; rawfile smartctl; f=$RAWF
    smartctl -H -A "/dev/$DEV" >"$f" 2>&1; rc=$?
    if (( rc & 2 )) || grep -qiE 'Unknown USB bridge|Unsupported|not supported|Unable to detect device type' "$f"; then
        note "No SMART data (normal for SD readers and most USB sticks)."
        return 0
    fi
    if grep -qE 'self-assessment test result: FAILED|Health Status: .*(FAIL|IMPENDING)' "$f"; then
        finding 2 "SMART overall health: FAILED" "The drive's own firmware predicts failure."
    elif grep -qE 'self-assessment test result: PASSED|SMART Health Status: OK' "$f"; then
        finding 0 "SMART overall health: PASSED"
    fi
    local id raw
    while read -r id raw; do
        [[ $raw =~ ^[0-9]+$ ]] || continue
        case $id in
            5)       (( raw > 0 )) && finding 1 "SMART: $raw reallocated sectors" "The drive has already replaced failing sectors." ;;
            197|198) (( raw > 0 )) && { N_UNREADABLE=$(( N_UNREADABLE + raw )); finding 2 "SMART attribute $id: $raw pending/uncorrectable sectors" "The drive knows of sectors it cannot read: physical failure."; } ;;
        esac
    done < <(awk '$1 ~ /^(5|197|198)$/ {print $1, $10}' "$f")
}

# ------------------------------------------------------------- kernel log ---
get_kernel_log() {
    if dmesg >"$1" 2>/dev/null && [[ -s $1 ]]; then return 0; fi
    if have journalctl && journalctl -k -b -q --no-pager -o short-monotonic >"$1" 2>/dev/null && [[ -s $1 ]]; then return 0; fi
    return 1
}

# Echo a dedup key for a btrfs error line, scoped to its partition.
btrfs_key() {
    local part=$1 line=$2
    if [[ $line =~ on\ ([0-9]+) ]]; then echo "$part:blk:${BASH_REMATCH[1]}"
    elif [[ $line =~ ino\ ([0-9]+)\ off\ ([0-9]+) ]]; then echo "$part:ino:${BASH_REMATCH[1]}:${BASH_REMATCH[2]}"
    elif [[ $line =~ bytenr\ ([0-9]+) ]]; then echo "$part:data:${BASH_REMATCH[1]}"
    elif [[ $line =~ block\ ([0-9]+) ]]; then echo "$part:blk:${BASH_REMATCH[1]}"
    else echo "$part:line:${line#*] }"
    fi
}

RE_IO='I/O error|critical medium error|Medium Error|Unrecovered read error|error -84|EILSEQ|Sense Key : Hardware Error|data CRC error|rejecting I/O to offline device|device offlined'
RE_TIMEOUT='[Tt]imed? ?out|error -110|ETIMEDOUT'
RE_RESET='reset (high|full|super|low)[- ]?speed|[Rr]etry|[Rr]etrying|recovery failed|Card stuck|never left busy|reset done'
RE_UV='[Uu]nder-?voltage (detected|has occurred)'

kernel_checks() {
    section "Kernel log (this device)"
    local klog=$WORK/klog
    if ! get_kernel_log "$klog"; then
        skip_check "kernel log: neither dmesg nor journalctl -k is readable (run as root)"
        return 0
    fi
    N_UV_HOST=$(grep -cE "$RE_UV" "$klog")

    # Patterns that identify this device's messages.
    local -a pats=("\\b${DEV}(p?[0-9]+)?\\b")
    local devpath host scsi port
    devpath=$(readlink -f "$SYS/device" 2>/dev/null)
    if [[ $DEV == mmcblk* && -n $devpath ]]; then
        host=$(basename "$(dirname "$devpath")"); pats+=("\\b${host}:")
    fi
    if [[ -n $devpath && $devpath == */usb* ]]; then
        scsi=${devpath##*/}; [[ $scsi =~ ^[0-9:]+$ ]] && pats+=("sd ${scsi}:")
        port=$(tr '/' '\n' <<<"$devpath" | grep -E '^[0-9]+-[0-9.]+$' | tail -1)
        [[ -n $port ]] && pats+=("usb ${port}:")
    fi
    local re; re=$(IFS='|'; echo "${pats[*]}")

    # Only consider messages since the current medium was attached.
    local start
    if [[ $DEV == mmcblk* ]]; then
        start=$(grep -nE "\\b${DEV}: ${host:-mmc[0-9]+}:[0-9a-f]+ " "$klog" | tail -1 | cut -d: -f1)
    else
        start=$(grep -nE "\\[${DEV}\\] ([0-9]+ [0-9]+-byte logical blocks|Attached SCSI)" "$klog" | tail -1 | cut -d: -f1)
    fi
    if [[ -n $start ]]; then
        note "Considering kernel messages since this medium was attached (log line $start)."
    else
        start=1; note "Attach message not found; considering all kernel messages since boot."
    fi
    KSTART=$start
    local dlog; rawfile kernel-log-device; dlog=$RAWF
    tail -n +"$start" "$klog" | grep -E "$re" >"$dlog"

    N_KIO=$(grep -E "$RE_IO" "$dlog" | grep -vc 'Buffer I/O error')
    N_KTIMEOUT=$(grep -cE "$RE_TIMEOUT" "$dlog")
    N_KRESET=$(grep -cE "$RE_RESET" "$dlog")
    kv "I/O errors" "$N_KIO"
    kv "Timeouts" "$N_KTIMEOUT"
    kv "Resets / retries" "$N_KRESET"
    (( N_KIO > 0 )) && observe WARN "$N_KIO kernel I/O errors for /dev/$DEV" \
        "Reads or writes the card could not complete: physical failure (or, less often, a bad reader/cable)."
    (( N_KTIMEOUT + N_KRESET > 0 )) && finding 1 "$N_KTIMEOUT timeouts and $N_KRESET resets/retries" \
        "The card or reader is struggling to respond; dying cards and flaky USB readers both do this. Try another reader to tell them apart."

    # btrfs messages for this device's partitions: add to the shared error sets.
    local line part kc=0 kt=0
    while IFS= read -r line; do
        [[ $line =~ \(device\ ([a-z0-9]+)\) ]] && part=${BASH_REMATCH[1]} || part=$DEV
        if [[ $line == *"parent transid verify failed"* ]]; then
            add_key TRANSID_KEYS "$(btrfs_key "$part" "$line")"; kt=$((kt + 1))
        elif [[ $line == *"bad tree block"* ]]; then
            add_key BADTREE_KEYS "$(btrfs_key "$part" "$line")"; kc=$((kc + 1))
        elif [[ $line =~ checksum\ verify\ failed|csum\ failed ]]; then
            add_key CSUM_KEYS "$(btrfs_key "$part" "$line")"; kc=$((kc + 1))
        fi
        if [[ $line =~ errs:\ wr\ ([0-9]+),\ rd\ ([0-9]+),\ flush\ ([0-9]+),\ corrupt\ ([0-9]+),\ gen\ ([0-9]+) ]]; then
            KDEVSTATS[$part]="${BASH_REMATCH[1]} ${BASH_REMATCH[2]} ${BASH_REMATCH[3]} ${BASH_REMATCH[4]} ${BASH_REMATCH[5]}"
        fi
    done < <(grep -E 'BTRFS' "$dlog")
    (( kc > 0 )) && observe WARN "Kernel logged $kc btrfs checksum / bad tree block messages" "Data read back does not match what was written: failing flash cells."
    (( kt > 0 )) && observe WARN "Kernel logged $kt btrfs 'parent transid verify failed' messages" "Writes the filesystem expected are missing: lost writes."
    local ext; ext=$(grep -cE 'EXT4-fs error|FAT-fs .*error' "$dlog")
    (( ext > 0 )) && observe INFO "Kernel logged $ext ext4/FAT filesystem errors (see raw log; fsck results below are authoritative)"
    (( N_KIO + N_KTIMEOUT + N_KRESET + kc + kt + ext == 0 )) && finding 0 "No errors logged for this device"
}

power_checks() {
    section "Power"
    kv "Undervoltage (this host)" "$N_UV_HOST messages since boot"
    if have vcgencmd; then
        local t; t=$(vcgencmd get_throttled 2>/dev/null | sed -n 's/^throttled=//p')
        if [[ $t =~ ^0x[0-9a-fA-F]+$ ]]; then
            local v=$(( t )) msgs=()
            (( v & 0x1 ))     && msgs+=("under-voltage NOW")
            (( v & 0x10000 )) && msgs+=("under-voltage has occurred since boot")
            (( v & 0x4 ))     && msgs+=("throttled now")
            (( v & 0x40000 )) && msgs+=("throttling has occurred")
            THROTTLED="$t${msgs[*]:+ (${msgs[*]})}"
            (( v & 0x10001 )) && N_UV_HOST=$(( N_UV_HOST > 0 ? N_UV_HOST : 1 ))
        fi
        kv "vcgencmd get_throttled" "$THROTTLED"
    elif grep -qs 'Raspberry Pi' /proc/device-tree/model; then
        skip_check "vcgencmd get_throttled: vcgencmd not installed (libraspberrypi-bin / raspi-utils)"
    else
        kv "vcgencmd get_throttled" "n/a (not a Raspberry Pi)"
    fi
    (( N_UV_HOST > 0 )) && observe WARN "Undervoltage recorded on this host" \
        "Brown-outs interrupt writes in flight and cause exactly the lost-write pattern (parent transid errors)."
    note "Host power only matters if the card was used in this machine; the card's own logs (per partition below) show what happened in the Pi."
}

# ------------------------------------------------------------ filesystems ---
check_btrfs() {
    local p=$1 mnt=$2
    if ! have btrfs; then
        skip_check "btrfs checks on $p: btrfs-progs not installed"
        return 0
    fi

    # Superblock copies: generations must agree.
    local f; rawfile "dump-super-${p##*/}"; f=$RAWF
    btrfs inspect-internal dump-super -a "$p" >"$f" 2>&1
    local total gens=() line off gen magic csum logroot maxgen=0 bad=0
    total=$(awk '/^dev_item.total_bytes/ {print $2; exit}' "$f")
    while read -r line; do
        set -- $line
        case $1 in
            SB)
                off=$2 gen=$3 magic=$4 csum=$5 logroot=$6
                if [[ $magic != ok ]]; then
                    add_key CSUM_KEYS "${p##*/}:super:$off"; bad=1
                    observe WARN "Superblock copy at $off has a bad magic number" "A metadata copy is missing or overwritten."
                elif [[ $csum == bad ]]; then
                    add_key CSUM_KEYS "${p##*/}:super:$off"; bad=1
                    observe WARN "Superblock copy at $off fails its checksum" "Corrupted on the flash: failing cells."
                else
                    gens+=("$off:$gen"); (( gen > maxgen )) && maxgen=$gen
                    if [[ $off == 65536 && -n $logroot && $logroot != 0 ]]; then
                        N_UNCLEAN=$((N_UNCLEAN + 1))
                        observe INFO "Primary superblock has a pending tree log (log_root=$logroot)" "The filesystem was not unmounted cleanly (unsafe shutdown or power loss)."
                    fi
                fi ;;
            BADMAGIC)
                if [[ -n $total ]] && (( $2 + 4096 <= total )); then
                    add_key CSUM_KEYS "${p##*/}:super:$2"; bad=1
                    observe WARN "Superblock copy at $2 is missing (bad magic) although the filesystem covers it" "Zeroed or overwritten metadata; on a large card this can also mean fake capacity."
                fi ;;
        esac
    done < <(awk '
        function out() { if (n) print "SB", off, gen, magic, csum, logroot }
        /^superblock: bytenr=/ { out(); n++; off=$2; sub(/^bytenr=/,"",off); sub(/,$/,"",off); gen=""; magic="bad"; csum=""; logroot="" ; next }
        /^csum[ \t]/   { csum = ($0 ~ /\[match\]/) ? "ok" : "bad" }
        /^magic[ \t]/  { magic = ($0 ~ /\[match\]/) ? "ok" : "bad" }
        /^generation[ \t]/ { gen = $2 }
        /^log_root[ \t]/   { logroot = $2 }
        /bad magic on superblock/ && match($0, /at [0-9]+/) { print "BADMAGIC", substr($0, RSTART+3, RLENGTH-3) }
        END { out() }' "$f")
    local g stale=0 detail=""
    for g in "${gens[@]}"; do
        detail+="${g%%:*}=gen ${g#*:}  "
        (( ${g#*:} != maxgen )) && stale=$((stale + 1))
    done
    kv "Superblock generations" "${detail:-none readable}"
    if (( stale > 0 )); then
        N_SUPERGEN=$((N_SUPERGEN + stale))
        observe WARN "$stale superblock copies disagree with the newest generation ($maxgen)" \
            "Interrupted or lost writes: the copies are written together at every commit, so a mismatch means the card did not complete (or silently dropped) a commit."
    elif (( ${#gens[@]} > 1 )) && (( ! bad )); then
        finding 0 "All ${#gens[@]} superblock copies agree (generation $maxgen)"
    fi

    # Full read-only metadata check (only safe when unmounted).
    if [[ -n $mnt ]]; then
        skip_check "btrfs check on $p: mounted at $mnt (unmount and re-run for a full metadata check)"
    else
        local args=(--readonly)
        (( MODE_FULL )) && args+=(--check-data-csum)
        rawfile "btrfs-check-${p##*/}"; f=$RAWF
        note "Running btrfs check ${args[*]} on $p (slow on large cards)..."
        btrfs check "${args[@]}" "$p" >"$f" 2>&1
        local rc=$? c0=${#CSUM_KEYS[@]} b0=${#BADTREE_KEYS[@]} t0=${#TRANSID_KEYS[@]} other=0 openfail=0 fststale=0 kind val
        while IFS=' ' read -r kind val; do
            case $kind in
                TRANSID) add_key TRANSID_KEYS "${p##*/}:blk:$val" ;;
                CSUM)    add_key CSUM_KEYS "${p##*/}:blk:$val" ;;
                FOUND)   [[ " ${CSUM_FOUND[${p##*/}:${val%%:*}]:-} " == *" ${val#*:} "* ]] ||
                             CSUM_FOUND[${p##*/}:${val%%:*}]+=" ${val#*:}" ;;
                DATA)    add_key CSUM_KEYS "${p##*/}:data:$val" ;;
                BADTREE) add_key BADTREE_KEYS "${p##*/}:blk:$val" ;;
                ZEROED)  N_ZEROED=$((N_ZEROED + 1)) ;;
                FOREIGN) N_WRAPPED=$((N_WRAPPED + 1)) ;;
                OTHER)   other=$((other + 1)) ;;
                OPENFAIL) openfail=1 ;;
                FSTSTALE) fststale=$((fststale + 1)) ;;
            esac
        done < <(awk '
            function num(re) { match($0, re); s = substr($0, RSTART, RLENGTH); gsub(/[^0-9]/, "", s); return s }
            /parent transid verify failed on [0-9]+/ { print "TRANSID", num("on [0-9]+"); next }
            /checksum verify failed on [0-9]+/       {
                b = num("on [0-9]+"); print "CSUM", b
                if (match($0, /found 0x[0-9a-fA-F]+/)) print "FOUND", b ":" substr($0, RSTART + 6, RLENGTH - 6)
                next }
            /bad tree block [0-9]+/ {
                print "BADTREE", num("block [0-9]+")
                if (match($0, /want=[0-9]+, have=[0-9]+/)) {
                    split(substr($0, RSTART, RLENGTH), w, /[=, ]+/)
                    print (w[4] == 0 ? "ZEROED" : "FOREIGN"), w[4]
                }
                next }
            /^mirror [0-9]+ bytenr [0-9]+ csum/      { print "DATA", num("bytenr [0-9]+"); next }
            /cannot open file system|Couldn.t open file system|No valid Btrfs found/ { print "OPENFAIL", 0; next }
            /space info key for a block group that doesn.t exist/ { print "FSTSTALE", 0; next }
            /^ERROR:/ && !/errors found in/          { print "OTHER", 0; next }
            /^root [0-9]+ inode [0-9]+ errors/       { print "OTHER", 0; next }' "$f")
        # The same block giving different data on each read: unstable cells.
        local k w unstable=0
        for k in "${!CSUM_FOUND[@]}"; do
            [[ $k == "${p##*/}:"* ]] || continue
            read -ra w <<<"${CSUM_FOUND[$k]}"
            (( ${#w[@]} > 1 )) && unstable=$((unstable + 1))
        done
        if (( unstable > 0 )); then
            N_UNSTABLE=$((N_UNSTABLE + unstable))
            finding 2 "$unstable metadata blocks read back with DIFFERENT data on repeated reads" \
                "A healthy card always returns the same data. Changing data means unstable flash cells: hardware failure, not power or an unsafe shutdown."
        fi
        local dc=$(( ${#CSUM_KEYS[@]} - c0 )) db=$(( ${#BADTREE_KEYS[@]} - b0 )) dt=$(( ${#TRANSID_KEYS[@]} - t0 ))
        N_BTRFS_OTHER=$((N_BTRFS_OTHER + other))
        kv "btrfs check exit code" "$rc"
        if (( openfail )); then
            finding 1 "btrfs check could not open the filesystem on $p" "Critical metadata is unreadable: the filesystem cannot be mounted and its data is lost."
        fi
        (( dc > 0 )) && observe WARN "btrfs check: $dc checksum failures" "Data or metadata read back differs from what was written: failing flash cells."
        (( db > 0 )) && observe WARN "btrfs check: $db bad tree blocks" "Metadata blocks are damaged: failing flash cells."
        (( dt > 0 )) && observe WARN "btrfs check: $dt 'parent transid verify failed'" "A block holds an older version than its parent expects: lost writes, which points at power loss or unsafe shutdown rather than dead cells."
        (( N_ZEROED > 0 )) && observe WARN "$N_ZEROED tree blocks read back as all zeros" "Data that was written is gone. Zeroed data high on the device is a sign of fake capacity."
        (( N_WRAPPED > 0 )) && observe WARN "$N_WRAPPED tree blocks contain a different block's data" "Writes landed at the wrong address; typical of fake-capacity cards that wrap around."
        if (( other > 0 )); then
            observe INFO "btrfs check: $other other structural errors" \
                "Usually knock-on effects of the errors above$( (( dt > 0 )) && echo ' (especially lost writes)'); see raw output."
            (( dc + db + dt == 0 )) && finding 1 "btrfs check found structural errors on $p without checksum or transid failures" "Inconsistent metadata; possibly lost writes. Inspect the raw output."
        fi
        (( fststale > 0 )) && finding 0 "btrfs check: $fststale stale free-space-tree entries" \
            "Harmless bookkeeping leftovers, not damage; the kernel removes them at the next mount."
        if (( rc != 0 && dc + db + dt + other + openfail + fststale == 0 )); then
            finding 1 "btrfs check exited $rc but reported nothing this script recognises" "See the raw output in the log."
        elif (( dc + db + dt + other + openfail == 0 )); then
            finding 0 "btrfs check: $( (( fststale )) && echo 'no damage found' || echo 'no errors')"
        fi
    fi

    # Persistent device error counters.
    local stats=""
    if [[ -n $mnt ]]; then
        rawfile "device-stats-${p##*/}"; f=$RAWF
        btrfs device stats "$p" >"$f" 2>&1 && \
            stats=$(awk -F'[. \t]+' '/write_io_errs/{w=$NF} /read_io_errs/{r=$NF} /flush_io_errs/{fl=$NF} /corruption_errs/{c=$NF} /generation_errs/{g=$NF} END{if (w!="") print w, r, fl, c, g}' "$f")
    else
        rawfile "dev-tree-${p##*/}"; f=$RAWF
        btrfs inspect-internal dump-tree -t dev "$p" >"$f" 2>&1
        stats=$(sed -nE 's/.*write_errs ([0-9]+) read_errs ([0-9]+) flush_errs ([0-9]+) corruption_errs ([0-9]+) generation ([0-9]+).*/\1 \2 \3 \4 \5/p' "$f" | head -1)
    fi
    [[ -z $stats && -n ${KDEVSTATS[${p##*/}]:-} ]] && stats=${KDEVSTATS[${p##*/}]}
    if [[ -n $stats ]]; then
        local w r fl c gn
        read -r w r fl c gn <<<"$stats"
        kv "Device stats" "write $w, read $r, flush $fl, corruption $c, generation $gn"
        local sum=$(( w + r + fl + c + gn ))
        N_DEVCNT=$(( N_DEVCNT + sum ))
        (( w + r + fl > 0 )) && observe WARN "btrfs has recorded $((w + r + fl)) I/O errors on $p" "Reads/writes that failed at the device: physical failure."
        (( c > 0 )) && observe WARN "btrfs has recorded $c corruption errors on $p" "Checksum mismatches seen during normal use: failing cells."
        (( gn > 0 )) && observe WARN "btrfs has recorded $gn generation errors on $p" "Stale blocks: lost writes."
        (( sum == 0 )) && finding 0 "btrfs device stats: all zero"
    else
        note "btrfs persistent error counters not available for $p."
    fi
}

check_ext() {
    local p=$1 mnt=$2 recovery=0 f
    if have dumpe2fs; then
        rawfile "dumpe2fs-${p##*/}"; f=$RAWF
        dumpe2fs -h "$p" >"$f" 2>&1
        local state feats errs ferr lerr
        state=$(sed -n 's/^Filesystem state: *//p' "$f")
        feats=$(sed -n 's/^Filesystem features: *//p' "$f")
        errs=$(sed -n 's/^FS Error count: *//p' "$f")
        ferr=$(sed -n 's/^First error function: *//p' "$f")
        lerr=$(sed -n 's/^Last error function: *//p' "$f")
        kv "State" "${state:-unknown}"
        if [[ $feats == *needs_recovery* && -z $mnt ]]; then
            recovery=1; N_UNCLEAN=$((N_UNCLEAN + 1))
            observe INFO "Journal needs recovery" "The filesystem was not unmounted cleanly: unsafe shutdown or power loss."
        fi
        if [[ $errs =~ ^[0-9]+$ ]] && (( errs > 0 )); then
            N_FSINCON=$((N_FSINCON + errs))
            observe WARN "Kernel recorded $errs runtime errors in the superblock (first: ${ferr:-?}, last: ${lerr:-?})" \
                "ext4 hit corruption or I/O errors while the card was in use."
        fi
    else
        skip_check "dumpe2fs on $p: e2fsprogs not installed"
    fi

    if [[ -n $mnt ]]; then
        skip_check "e2fsck on $p: mounted at $mnt (unmount and re-run for a full check)"; return 0
    fi
    have e2fsck || { skip_check "e2fsck on $p: e2fsprogs not installed"; return 0; }
    rawfile "e2fsck-${p##*/}"; f=$RAWF
    e2fsck -fn "$p" >"$f" 2>&1 </dev/null
    local rc=$? io cs acct other
    # Each "...? no" is one problem e2fsck would fix; classify by its text.
    read -r io cs acct other < <(awk '
        { if ($0 ~ /^[A-Za-z ]*\? no$/) text = prev; else text = $0; prev = $0 }
        /Error reading block|Attempt to read block|[Ss]hort read|Error while (reading|iterating)|I\/O error/ { io++; next }
        !/\? no$/ { next }
        text ~ /checksum|csum/ { cs++; next }
        text ~ /Free (blocks|inodes) count wrong|(Block|Inode) bitmap differences|Padding at end of/ { acct++; next }
        { other++ }
        END { print io+0, cs+0, acct+0, other+0 }' "$f")
    kv "e2fsck exit code" "$rc"
    if (( io > 0 )); then
        N_UNREADABLE=$((N_UNREADABLE + io))
        finding 2 "e2fsck could not read $io blocks on $p" "Unreadable sectors: physical failure."
    fi
    if (( recovery )); then
        (( cs + other + acct > 0 )) && observe INFO "e2fsck reported $((cs + other + acct)) issues, but the journal was not replayed" \
            "These are not counted: most will disappear once the journal is replayed (mount the card once, or e2fsck -p a copy), then re-run."
        return 0
    fi
    local i
    for (( i = 1; i <= cs; i++ )); do add_key CSUM_KEYS "${p##*/}:ext:$i"; done
    N_FSINCON=$((N_FSINCON + other))
    (( cs > 0 )) && observe WARN "e2fsck: $cs metadata checksum mismatches on $p" "Metadata changed on the flash after it was written: failing cells."
    (( other > 0 )) && observe WARN "e2fsck: $other filesystem inconsistencies on $p" "Real corruption: from failing cells or writes lost to power problems."
    (( acct > 0 )) && observe INFO "e2fsck: $acct free-space accounting differences (harmless, typical after an unclean shutdown)"
    (( rc == 8 )) && finding 1 "e2fsck could not check $p (operational error)" "The superblock may be unreadable; see raw output."
    (( io + cs + other == 0 && rc != 8 )) && finding 0 "e2fsck: no errors"
}

check_vfat() {
    local p=$1 mnt=$2 f
    have fsck.fat || { skip_check "fsck.fat on $p: dosfstools not installed"; return 0; }
    rawfile "fsck.fat-${p##*/}"; f=$RAWF
    fsck.fat -n "$p" >"$f" 2>&1 </dev/null
    local rc=$? io dirty other
    read -r io dirty other < <(awk '
        /^[ \t]/ || /^$/ { next }
        /^fsck\.fat |^dosfsck |files, .*clusters|^Leaving file ?system unchanged|^Free cluster summary|^There are differences between boot sector and its backup|^This is mostly harmless|^Not automatically fixing|^There is no label in boot sector|^No-operation mode|^Checking we can access/ { next }
        /[Rr]ead error|Unable to read|[Ss]eek .*failed|[Ss]hort read|I\/O error/ { io++; next }
        /Dirty bit is set/ { dirty++; next }
        { other++ }
        END { print io+0, dirty+0, other+0 }' "$f")
    kv "fsck.fat exit code" "$rc"
    if (( io > 0 )); then
        N_UNREADABLE=$((N_UNREADABLE + io))
        finding 2 "fsck.fat could not read $io regions of $p" "Unreadable sectors: physical failure."
    fi
    if (( dirty > 0 )) && [[ -z $mnt ]]; then
        N_UNCLEAN=$((N_UNCLEAN + 1))
        observe INFO "FAT dirty bit set" "Not unmounted cleanly: unsafe shutdown or power loss."
    fi
    N_FSINCON=$((N_FSINCON + other))
    (( other > 0 )) && observe WARN "fsck.fat: $other inconsistencies on $p$( [[ -n $mnt ]] && echo ' (mounted: may include in-flight changes)')" \
        "Real corruption: from failing cells or writes lost to power problems."
    (( io + other == 0 )) && finding 0 "fsck.fat: no errors"
}

# Undervoltage and I/O errors recorded by the Pi itself, from the card's logs.
card_logs() {
    local p=$1 fstype=$2 mnt=$3 uv=0 io=0 src="" text
    text=$WORK/cardlog
    : >"$text"
    if [[ -n $mnt ]]; then
        local lf
        for lf in "$mnt"/var/log/kern.log* "$mnt"/var/log/syslog* "$mnt"/var/log/messages*; do
            [[ -f $lf ]] || continue
            zcat -f -- "$lf" >>"$text" 2>/dev/null; src+="${lf#"$mnt"} "
        done
        if have journalctl && [[ -d $mnt/var/log/journal ]]; then
            journalctl -D "$mnt/var/log/journal" -k -q --no-pager -o short >>"$text" 2>/dev/null && src+="journal "
        fi
    elif [[ $fstype == ext* ]] && have debugfs; then
        local lf
        for lf in /var/log/kern.log /var/log/syslog /var/log/messages; do
            # -c: catastrophic mode, opens read-only and skips bitmaps.
            if debugfs -c -R "cat $lf" "$p" >>"$text" 2>/dev/null; then src+="$lf "; fi
        done
        [[ -s $text ]] || src=""
    fi
    [[ -s $text ]] || { [[ $fstype == btrfs && -z $mnt ]] && note "The card's own logs on an unmounted btrfs are not read (mount it read-only to include them)."; return 0; }
    uv=$(grep -cE "$RE_UV" "$text")
    io=$(grep -E 'mmcblk0' "$text" | grep -E "$RE_IO|error -110" | grep -vc 'Buffer I/O error')
    N_UV_CARD=$((N_UV_CARD + uv)); N_CARD_IO=$((N_CARD_IO + io))
    kv "Card's own logs" "${src:-none}"
    kv "  undervoltage events" "$uv"
    kv "  SD I/O errors in Pi" "$io"
    (( uv > 0 )) && observe WARN "The Pi logged $uv undervoltage events while running from this card" \
        "Undervoltage interrupts writes: corruption here is likely caused by the power supply, not the card."
    (( io > 0 )) && observe WARN "The Pi logged $io SD-card I/O errors / timeouts while running from this card" \
        "The card misbehaved in service: points at a failing card (or undervoltage, if also logged)."
}

# ------------------------------------------------------ generation history ---
# A monotonic counter per filesystem: btrfs superblock generation, or ext4
# s_kbytes_written (raw superblock field at byte 1024 + 0x178).
progress_value() {
    case $2 in
        btrfs)  have btrfs && btrfs inspect-internal dump-super -s 0 "$1" 2>/dev/null | awk '/^generation[ \t]/ {print $2; exit}' ;;
        ext3|ext4) od -An -t u8 -j 1400 -N 8 "$1" 2>/dev/null | tr -d ' ' ;;
    esac
}
# Native SD slots expose the card's unique CID; USB readers do not.
card_id() { readf "/sys/block/$DEV/device/cid"; }
history_file() {
    local uuid; uuid=$(blkid -p -o value -s UUID "$1" 2>/dev/null)
    [[ -n $uuid ]] || uuid=$(lsblk -dno UUID "$1" 2>/dev/null | tr -d ' ')
    [[ -n $uuid ]] || return 1
    # Cards flashed from one image share the filesystem UUID; the capacity
    # (and the CID, when the slot exposes it) tells them apart.
    local id size; id=$(card_id); size=$(readf "/sys/block/$DEV/size")
    printf '%s/%s-%s%s' "$STATE_DIR" "$uuid" "$size" "${id:+-$id}"
}
history_write() {  # history_write FILE VALUE HOW
    mkdir -p "$STATE_DIR" 2>/dev/null || return 0
    printf '%s %s %s\n' "$2" "$(date +%s)" "$3" >"$1.tmp" 2>/dev/null && mv -f "$1.tmp" "$1"
}
# First generation the kernel scanned for this partition after the medium was
# attached: what was on the card before anything mounted it.
kernel_scan_gen() {
    local f=$WORK/klog.now
    get_kernel_log "$f" || return 1
    tail -n +"$KSTART" "$f" | grep -E "transid [0-9]+ /dev/${1##*/} " | head -1 | sed -nE 's/.*transid ([0-9]+) .*/\1/p'
}

history_check() {
    local p=$1 fstype=$2 mnt=$3 file cur src
    [[ $fstype == btrfs || $fstype == ext3 || $fstype == ext4 ]] || return 0
    # Flasher cards all carry the same image, so history cannot tell them apart.
    (( FLASHER )) && return 0
    (( EUID == 0 )) || { note "Generation history needs root; skipped."; return 0; }
    file=$(history_file "$p") || return 0
    if [[ -z $mnt ]]; then
        cur=$(progress_value "$p" "$fstype"); src="read from the card"
    elif (( ! MODE_UDEV )); then
        # Records made during this insertion are newer than the insertion
        # scan, so comparing now would report a rollback that did not happen.
        note "Mounted: lost-write history is compared at insertion or when unmounted."
        return 0
    elif [[ $fstype == btrfs ]] && cur=$(kernel_scan_gen "$p") && [[ -n $cur ]]; then
        src="kernel scan at insertion, before mounting"
    else
        cur=$(progress_value "$p" "$fstype"); src="mounted: may include writes made since insertion"
    fi
    [[ $cur =~ ^[0-9]+$ ]] || return 0
    local unit=generation; [[ $fstype == btrfs ]] || unit="KiB written"
    kv "On-card $unit" "$cur  ($src)"
    if [[ ! -f $file ]]; then
        note "First time this filesystem is seen here; recording it for future comparisons."
        history_write "$file" "$cur" seen; return 0
    fi
    local prev when how
    read -r prev when how <"$file"
    kv "Last recorded" "$prev  ($how $(date -d "@$when" '+%F %T' 2>/dev/null))"
    if (( cur < prev )); then
        local drop=$(( prev - cur )) other_card=0 caveat=""
        if [[ $fstype == btrfs ]]; then (( drop > ROLLBACK_MAX )) && other_card=1
        else (( cur * 2 < prev )) && other_card=1; fi
        if (( other_card )); then
            note "Counter dropped from $prev to $cur: this looks like a reflashed or different card, not lost writes. History reset."
        else
            [[ -z $(card_id) ]] && caveat=" (Unless you reflashed this card, or it is another card of the same size flashed from the same image: this reader cannot tell such cards apart.)"
            local lostn=1; [[ $fstype == btrfs ]] && lostn=$drop
            N_ROLLBACK=$(( N_ROLLBACK + lostn ))
            observe WARN "Filesystem went BACKWARDS: this computer last wrote $unit $prev, but the card now holds $cur" \
                "The card (or reader) confirmed writes and then lost them: the last $( [[ $fstype == btrfs ]] && echo "$drop commit(s)" || echo "superblock update") never reached the flash. This happened here, not on the Pi, so it is not the Pi's power supply.$caveat"
        fi
        history_write "$file" "$cur" seen
    elif (( cur > prev )); then
        note "Counter advanced since last time ($prev -> $cur): used elsewhere since, nothing lost."
        history_write "$file" "$cur" seen
    else
        finding 0 "Counter matches what was last written ($cur): no lost writes since last time"
    fi
}

# --track: while the card is present, record every new counter value this
# host writes, so the next insertion can detect a rollback.
track() {
    trap 'exit 0' TERM INT HUP
    (( EUID == 0 )) || { echo "$PROG: --track needs root" >&2; exit 3; }
    [[ -n $FLASHER_IMAGE ]] && reader_number >/dev/null && exit 0
    local p fstype file v prev
    while [[ -e /sys/block/$DEV ]]; do
        while read -r p; do
            fstype=$(lsblk -dno FSTYPE "$p" 2>/dev/null | tr -d ' ')
            [[ $fstype == btrfs || $fstype == ext3 || $fstype == ext4 ]] || continue
            file=$(history_file "$p") || continue
            v=$(progress_value "$p" "$fstype")
            [[ $v =~ ^[0-9]+$ ]] || continue
            prev=0; [[ -f $file ]] && read -r prev _ <"$file"
            if (( v > prev )); then
                history_write "$file" "$v" written
            fi
        done < <(lsblk -nrpo NAME,TYPE "/dev/$DEV" 2>/dev/null | awk '$2=="part" || NR==1 {print $1}')
        sleep "$TRACK_INTERVAL" & wait $!
    done
    exit 0
}

# ----------------------------------------------------------- mount handling ---
# "name uid" for each user with an active graphical session.
graphical_users() {
    have loginctl || return 0
    local sid props name uid type active class
    local -A seen=()
    for sid in $(loginctl list-sessions --no-legend 2>/dev/null | awk '{print $1}'); do
        props=$(loginctl show-session "$sid" -p Name -p User -p Type -p Active -p Class 2>/dev/null)
        name=$(sed -n 's/^Name=//p' <<<"$props");   uid=$(sed -n 's/^User=//p' <<<"$props")
        type=$(sed -n 's/^Type=//p' <<<"$props");   active=$(sed -n 's/^Active=//p' <<<"$props")
        class=$(sed -n 's/^Class=//p' <<<"$props")
        [[ $type == x11 || $type == wayland || $type == mir ]] || continue
        [[ $active == yes && $class == user* && -n $uid && -z ${seen[$uid]:-} ]] || continue
        seen[$uid]=1; echo "$name $uid"
    done
}

# Mount through udisks on behalf of USER, exactly like a desktop automount.
mount_for_user() {
    local p=$1 user=$2 obj out
    have gdbus || { note "gdbus not installed; mount $p from the file manager."; return 1; }
    obj=/org/freedesktop/UDisks2/block_devices/${p##*/}
    out=$(gdbus call --system --dest org.freedesktop.UDisks2 --object-path "$obj" \
            --method org.freedesktop.UDisks2.Filesystem.Mount "{'as-user': <'$user'>}" 2>&1)
    if [[ $out =~ \(\'([^\']+)\' ]]; then
        MOUNTED_MSGS+=("$p at ${BASH_REMATCH[1]}"); note "Mounted $p at ${BASH_REMATCH[1]} for $user."
    else
        note "Could not mount $p for $user: ${out:0:200}"; return 1
    fi
}

# Unmount a desktop automount so the full checks can run.
unmount_for_check() {
    local p=$1 mnt=$2 user
    case $mnt in /run/media/*|/media/*) ;; *) return 1 ;; esac
    user=${mnt#/run/media/}; user=${user#/media/}; user=${user%%/*}
    id "$user" >/dev/null 2>&1 || user=${SUDO_USER:-}
    if have udisksctl; then udisksctl unmount -b "$p" --no-user-interaction >/dev/null 2>&1; fi
    [[ -n $(findmnt -nro TARGET -S "$p" 2>/dev/null) ]] && umount "$p" 2>/dev/null
    if [[ -n $(findmnt -nro TARGET -S "$p" 2>/dev/null) ]]; then
        note "Could not unmount $p (in use?); checking it mounted."
        return 1
    fi
    note "Unmounted $p for the check (will mount it back${user:+ for $user})."
    REMOUNT+=("$p ${user:-}")
}

# Mount back what we unmounted; in udev mode also do the held automount.
finish_mounts() {
    local entry p user fstype
    for entry in "${REMOUNT[@]}"; do
        read -r p user <<<"$entry"
        [[ -e $p && -z $(findmnt -nro TARGET -S "$p" 2>/dev/null) ]] || continue
        if [[ -n $user ]]; then mount_for_user "$p" "$user"; else note "Unmounted $p was not remounted (owner unknown)."; fi
    done
    REMOUNT=()
    (( (MODE_UDEV || ${SDCARD_WATCH:-0}) && AUTOMOUNT_AFTER )) || return 0
    [[ -e $SYS ]] || return 0
    read -r user _ < <(graphical_users)
    [[ -n ${user:-} ]] || { note "No one is logged in graphically; leaving the card unmounted."; return 0; }
    while read -r p; do
        [[ -z $(findmnt -nro TARGET -S "$p" 2>/dev/null) ]] || continue
        fstype=$(blkid -p -o value -s TYPE "$p" 2>/dev/null)
        [[ -n $fstype ]] || fstype=$(lsblk -dno FSTYPE "$p" 2>/dev/null | tr -d ' ')
        case $fstype in
            vfat|exfat|ntfs|ntfs3|btrfs|xfs|f2fs|iso9660|udf|hfsplus) ;;
            ext2|ext3|ext4) (( AUTOMOUNT_EXT )) || continue ;;
            *) continue ;;
        esac
        mount_for_user "$p" "$user"
    done < <(lsblk -nrpo NAME,TYPE "/dev/$DEV" 2>/dev/null | awk '$2=="part" || NR==1 {print $1}')
}

partition_checks() {
    local -a parts
    mapfile -t parts < <(lsblk -nrpo NAME,TYPE "/dev/$DEV" 2>/dev/null | awk '$2=="part"{print $1}')
    (( ${#parts[@]} )) || parts=("/dev/$DEV")
    local p fstype mnt label
    if (( AUTO_UNMOUNT && EUID == 0 )); then
        for p in "${parts[@]}"; do
            mnt=$(findmnt -nro TARGET -S "$p" 2>/dev/null | head -1)
            [[ -n $mnt ]] && unmount_for_check "$p" "$mnt"
        done
    fi
    # Drop the kernel's cached copy of unmounted partitions so every check
    # reads the card itself, not what Linux remembers writing to it.
    # Nothing is dirty when unmounted, so this writes nothing.
    if (( EUID == 0 )) && have blockdev; then
        local nm=0
        for p in "${parts[@]}"; do
            if [[ -z $(findmnt -nro TARGET -S "$p" 2>/dev/null) ]]; then blockdev --flushbufs "$p" 2>/dev/null; else nm=1; fi
        done
        (( nm )) || blockdev --flushbufs "/dev/$DEV" 2>/dev/null
    fi
    for p in "${parts[@]}"; do
        fstype=$(blkid -p -o value -s TYPE "$p" 2>/dev/null)
        label=$(blkid -p -o value -s LABEL "$p" 2>/dev/null)
        # Fall back to udev's cached probe if the low-level probe fails.
        [[ -n $fstype ]] || fstype=$(lsblk -dno FSTYPE "$p" 2>/dev/null | tr -d ' ')
        [[ -n $label ]] || label=$(lsblk -dno LABEL "$p" 2>/dev/null)
        mnt=$(findmnt -nro TARGET -S "$p" 2>/dev/null | head -1)
        section "Partition $p (${fstype:-no filesystem}${label:+, label $label}${mnt:+, mounted at $mnt})"
        case $fstype in
            btrfs)            check_btrfs "$p" "$mnt" ;;
            ext2|ext3|ext4)   check_ext "$p" "$mnt" ;;
            vfat)             check_vfat "$p" "$mnt" ;;
            "")               note "No recognisable filesystem." ;;
            *)                note "No checker for $fstype." ;;
        esac
        [[ -n $fstype ]] && card_logs "$p" "$fstype" "$mnt"
        history_check "$p" "$fstype" "$mnt"
    done
}

# ----------------------------------------------------- fake capacity probe ---
# Read-only. Fake cards map addresses beyond their real capacity back onto
# low addresses (wrap-around), or return zeros/errors there. Sample blocks in
# the upper part of the device and compare with the block they would alias.
read_block() {  # read_block OFFSET_IN_4K_BLOCKS FILE; error text in $WORK/rd.err
    timeout 30 "$DD" if="/dev/$DEV" of="$2" bs=4096 skip="$1" count=1 "${DDIN[@]}" status=none 2>"$WORK/rd.err" &&
        [[ $(stat -c %s "$2" 2>/dev/null) == 4096 ]]
}
trivial_block() { (( $(od -An -v -tx1 -w16 "$1" | sort -u 2>/dev/null | head -3 | wc -l) <= 2 )); }

fake_capacity_probe() {
    section "Fake-capacity probe (read-only)"
    local nblk=$(( SIZE_BYTES / 4096 )) k off blank=0 errs=0 nontriv=0
    local -A match=()
    local hb=$WORK/hi.blk lb=$WORK/lo.blk
    for (( k = 1; k <= FAKE_SAMPLES; k++ )); do
        off=$(( nblk / 4 + (nblk * 3 / 4) * k / (FAKE_SAMPLES + 1) + 37 * k ))
        (( off < nblk )) || off=$(( nblk - 1 ))
        if ! read_block "$off" "$hb"; then
            if grep -qE "$RE_MEDIA_ERR" "$WORK/rd.err" || [[ ! -s $WORK/rd.err ]]; then
                errs=$((errs + 1)); N_UNREADABLE=$(( N_UNREADABLE + 4096 / LBS ))
                observe FAIL "Read error at offset $(human $(( off * 4096 )))" "Unreadable sector. Errors only at high offsets are also typical of fake capacity."
            else
                TOOL_ERRS=$((TOOL_ERRS + 1))
                note "Could not sample offset $(human $(( off * 4096 ))): $(head -1 "$WORK/rd.err") (tool problem, not counted)"
            fi
            continue
        fi
        if trivial_block "$hb"; then blank=$((blank + 1)); continue; fi
        nontriv=$((nontriv + 1))
        local hsum p=$(( FAKE_MIN_REAL_MB * 1024 * 1024 / 4096 ))
        hsum=$(cksum <"$hb")
        while (( p < off )); do
            if read_block $(( off % p )) "$lb" && [[ $(cksum <"$lb") == "$hsum" ]]; then
                match[$p]=$(( ${match[$p]:-0} + 1 ))
            fi
            p=$(( p * 2 ))
        done
    done
    kv "Samples" "$FAKE_SAMPLES in the upper 3/4 of the device: $nontriv with data, $blank blank, $errs unreadable"
    local p best=0 bestp=0
    for p in "${!match[@]}"; do (( match[$p] > best )) && { best=${match[$p]}; bestp=$p; }; done
    if (( best >= 2 )); then
        FLAG_FAKE=1
        N_WRAPPED=$((N_WRAPPED + best))
        finding 2 "Data wraps around: $best high blocks are identical to the blocks $(human $(( bestp * 4096 ))) lower" \
            "Classic fake-capacity card: real capacity is probably about $(human $(( bestp * 4096 ))). Confirm with --destructive (f3probe)."
    elif (( best == 1 )); then
        finding 1 "One high block is identical to its wrap-around position" "Weak evidence of fake capacity (could be a coincidence). Confirm with --destructive (f3probe)."
    else
        finding 0 "No wrap-around found"
    fi
    if (( blank * 4 >= FAKE_SAMPLES * 3 && N_ZEROED > 0 )); then
        finding 1 "Upper area reads blank and the filesystem has zeroed metadata" \
            "Likely fake capacity: data written high on the card has vanished. Confirm with --destructive (f3probe)."
    elif (( blank * 4 >= FAKE_SAMPLES * 3 )); then
        note "Most of the upper area is blank. That is normal for unused space; it only means fake capacity if the filesystem expects data there."
    fi
}

# --------------------------------------------------------- manual modes -----
full_scan() {
    section "Full read scan (dd conv=noerror,sync)"
    local chunk=$(( FULL_CHUNK_MB * 1024 * 1024 )) n i e rescans=0 approx=0
    n=$(( (SIZE_BYTES + chunk - 1) / chunk ))
    local err=$WORK/dd.err t0=$SECONDS lastpct=-10 bad_regions=()
    for (( i = 0; i < n; i++ )); do
        [[ -e $SYS ]] || { finding 2 "Device disappeared during the scan" "The card dropped off the bus: severe failure or removed."; break; }
        "$DD" if="/dev/$DEV" of=/dev/null bs=1M skip=$(( i * FULL_CHUNK_MB )) count="$FULL_CHUNK_MB" \
            "${DDIN[@]}" conv=noerror,sync status=none 2>"$err"
        e=$(grep -cE "$RE_MEDIA_ERR" "$err")
        if (( e == 0 )) && [[ -s $err ]]; then
            die "read scan stopped at $(human $(( i * chunk ))): $DD failed with: $(head -1 "$err")"
        fi
        if (( e > 0 )); then
            bad_regions+=("$(human $(( i * chunk )))")
            if (( rescans < FULL_MAX_RESCAN )); then
                rescans=$((rescans + 1))
                "$DD" if="/dev/$DEV" of=/dev/null bs=4096 skip=$(( i * chunk / 4096 )) count=$(( chunk / 4096 )) \
                    "${DDIN[@]}" conv=noerror,sync status=none 2>"$err"
                e=$(grep -cE "$RE_MEDIA_ERR" "$err")
                N_UNREADABLE=$(( N_UNREADABLE + e * 4096 / LBS ))
            else
                approx=1; N_UNREADABLE=$(( N_UNREADABLE + e * 1048576 / LBS ))
            fi
        fi
        local pct=$(( (i + 1) * 100 / n ))
        if (( pct >= lastpct + 10 )); then
            lastpct=$pct
            local el=$(( SECONDS - t0 )); (( el > 0 )) || el=1
            note "read scan ${pct}%  $(human $(( (i + 1) * chunk )))  $(( (i + 1) * FULL_CHUNK_MB / el )) MB/s  unreadable so far: $N_UNREADABLE"
        fi
    done
    FULL_DONE=1
    if (( N_UNREADABLE > 0 )); then
        finding 2 "$( (( approx )) && echo 'at least ')$N_UNREADABLE unreadable sectors (regions starting at: ${bad_regions[*]:0:8})" \
            "Sectors the card cannot return at all: physical failure."
    else
        finding 0 "Every sector read back without error"
    fi
}

fingerprint() {
    printf '%s|%s|%s' "$(readf "$SYS/size")" "$(readf "$SYS/device/serial")$(readf "$SYS/device/cid")" "$(readlink -f "$SYS/device" 2>/dev/null)"
}
mounted_parts() { lsblk -nrpo NAME,MOUNTPOINTS "/dev/$DEV" 2>/dev/null | awk 'NF > 1 {print $1 " on " $2}'; }

confirm_destructive() {
    local m; m=$(mounted_parts)
    [[ -z $m ]] || die "--destructive: unmount first:"$'\n'"$m"
    {
        printf '\n!!! --destructive will OVERWRITE ALL DATA on /dev/%s\n' "$DEV"
        printf '    %s, %s\n' "$MODEL" "$(human "$SIZE_BYTES")"
        printf '    Type  ERASE %s  to continue: ' "$DEV"
    } >/dev/tty
    local answer; read -r answer </dev/tty
    [[ $answer == "ERASE $DEV" ]] || die "confirmation not given; nothing was written"
    echo "Destructive test confirmed by operator for /dev/$DEV."
    FINGERPRINT=$(fingerprint)
}

destructive_test() {
    section "Destructive test"
    [[ $(fingerprint) == "$FINGERPRINT" ]] || die "the device changed since confirmation (card swapped?); nothing was written"
    local m; m=$(mounted_parts)
    [[ -z $m ]] || die "a partition was mounted during the checks; nothing was written:"$'\n'"$m"
    local f
    if have f3probe; then
        rawfile f3probe; f=$RAWF
        note "Running f3probe --destructive --time-ops /dev/$DEV ..."
        f3probe --destructive --time-ops "/dev/$DEV" 2>&1 | tee "$f" | sed 's/^/      /'
        if grep -q 'is the real thing' "$f"; then
            finding 0 "f3probe: capacity is genuine"
        elif grep -q 'counterfeit' "$f"; then
            FLAG_FAKE=1
            finding 2 "f3probe: FAKE capacity ($(grep -m1 -i usable "$f" | sed "s/^ *//"))" "The card reports more space than it has; anything written past the real size is lost."
        elif grep -q 'damaged' "$f"; then
            N_UNREADABLE=$((N_UNREADABLE + 1))
            finding 2 "f3probe: the device is damaged" "It cannot reliably store data."
        else
            finding 1 "f3probe gave no verdict" "See raw output."
        fi
    elif have badblocks; then
        rawfile badblocks-list; f=$RAWF
        note "f3probe not installed; falling back to badblocks -wsv (slow; cannot detect fake capacity)."
        badblocks -wsv -b 4096 -o "$f" "/dev/$DEV"
        local nb; nb=$(grep -c . "$f")
        N_UNREADABLE=$(( N_UNREADABLE + nb * 4096 / LBS ))
        if (( nb > 0 )); then
            finding 2 "badblocks: $nb bad 4 KiB blocks" "The card cannot store data reliably: physical failure."
        else
            finding 0 "badblocks: no bad blocks (note: this test does not detect fake capacity)"
        fi
    else
        skip_check "destructive test: neither f3probe (f3) nor badblocks (e2fsprogs) installed"
    fi
}

# ---------------------------------------------------------------- verdict ---
V_LEVEL=0 V_LABEL=CLEAN V_REC="No problems found; the card looks healthy."
set_verdict() { if (( $1 > V_LEVEL )); then V_LEVEL=$1 V_LABEL=$2 V_REC=$3; fi; }

summarize() {
    local n_csum=${#CSUM_KEYS[@]} n_bad=${#BADTREE_KEYS[@]} n_tid=${#TRANSID_KEYS[@]}
    local corrupt=$(( n_csum + n_bad + N_FSINCON + N_DEVCNT ))
    local lost=$(( n_tid + N_SUPERGEN + N_ROLLBACK ))
    local kio=$(( N_KIO + N_CARD_IO ))

    # Most decisive first; the first rule to reach a level wins that level.
    (( FLAG_RO ))                      && set_verdict 2 "FAULTY (read-only)" "The card has locked itself read-only: copy off what you need and replace it (first check the lock slider)."
    (( FLAG_FAKE ))                    && set_verdict 2 "FAULTY (fake capacity)" "Counterfeit capacity: anything past the real size is lost. Return or discard the card."
    (( N_UNREADABLE > 0 ))             && set_verdict 2 "FAULTY (unreadable sectors)" "Back up anything still readable and replace the card."
    (( N_UNSTABLE > 0 ))               && set_verdict 2 "FAULTY (unstable reads)" "The card returns different data for the same block: its flash is failing. Replace it; do not reflash and reuse it."
    (( corrupt >= CORRUPT_FATAL ))     && set_verdict 2 "FAULTY (definite)" "The card cannot store data reliably. Replace it; do not reuse it after reflashing."
    (( corrupt >= CORRUPT_FAIL ))      && set_verdict 2 "FAULTY (probable)" "Widespread corruption: back up now and plan to replace the card."
    (( lost >= TRANSID_FAIL ))         && set_verdict 2 "FAULTY (dropping writes)" "At this volume the card itself is losing writes; replace it."
    (( kio >= KERNEL_IO_FAIL ))        && set_verdict 2 "FAULTY (I/O errors)" "Repeated I/O errors: back up and replace. If another reader shows none, suspect the reader."
    (( LEVEL >= 2 ))                   && set_verdict 2 "FAULTY" "See the FAIL findings above; replace the card."
    (( corrupt >= CORRUPT_WARN ))      && set_verdict 1 "SUSPICIOUS" "Real but limited corruption: run sdcard-check.sh --full and check the power supply before condemning the card."
    (( N_ROLLBACK > 0 && lost < TRANSID_FAIL )) && set_verdict 1 "SUSPICIOUS (lost writes)" "The card or reader dropped confirmed writes on this computer: repeat the test in another reader; if it follows the card, replace the card."
    (( lost >= TRANSID_WARN ))         && set_verdict 1 "SUSPICIOUS (lost writes)" "Suspect undervoltage or unclean shutdowns: use a proper 5V/3A+ supply, always shut down cleanly, reflash and re-check."
    (( kio >= KERNEL_IO_WARN ))        && set_verdict 1 "SUSPICIOUS (I/O errors)" "Run sdcard-check.sh --full; try a different reader to rule it out."
    (( LEVEL >= 1 ))                   && set_verdict 1 "SUSPICIOUS" "See the WARN findings above."

    section "SUMMARY"
    kv "checksum errors" "$n_csum"
    kv "bad tree blocks" "$n_bad"
    kv "fs inconsistencies" "$N_FSINCON"
    kv "device counters" "$N_DEVCNT  (btrfs device stats)"
    kv "  => corruption total" "$corrupt  (tiers: $CORRUPT_WARN / $CORRUPT_FAIL / $CORRUPT_FATAL)"
    kv "lost-write errors" "$lost  (parent transid $n_tid, superblock generation $N_SUPERGEN, rollback since last use here $N_ROLLBACK; tiers: $TRANSID_WARN / $TRANSID_FAIL)"
    kv "kernel I/O errors" "$kio  (this host $N_KIO, Pi's own logs $N_CARD_IO; timeouts $N_KTIMEOUT, resets $N_KRESET)"
    kv "unreadable sectors" "$N_UNREADABLE$( (( FULL_DONE )) || echo '  (full read scan not run; use --full)')"
    kv "undervoltage" "this host $N_UV_HOST, card's logs $N_UV_CARD, get_throttled $THROTTLED"
    kv "unclean shutdown signs" "$N_UNCLEAN"
    (( TOOL_ERRS )) && kv "tool read failures" "$TOOL_ERRS  (not media errors; not counted)"

    if (( N_ROLLBACK > 0 )); then
        echo
        note "The rollback was observed on THIS computer: the card or reader dropped writes it had confirmed. Repeat in another reader: if it follows the card, replace the card."
    fi
    if (( lost > N_ROLLBACK )); then
        echo
        note "Lost writes point at power loss/undervoltage or unsafe shutdowns rather than dead cells."
        if (( N_UV_HOST + N_UV_CARD > 0 )); then
            note "Undervoltage WAS recorded ($N_UV_CARD in the card's logs, $N_UV_HOST on this host): the power supply is the prime suspect."
        else
            note "No undervoltage found in the available logs. Pulling power without shutting down is the other usual cause."
        fi
    fi
    if (( ${#FINDINGS[@]} )); then
        echo; note "Findings:"
        printf '      %s\n' "${FINDINGS[@]}"
    fi
    if (( ${#SKIPPED[@]} )); then
        echo; note "Checks not performed:"
        printf '      %s\n' "${SKIPPED[@]}"
    fi

    VERDICT_LINE="$V_LABEL: $n_csum checksum errors, $n_bad bad tree blocks, $N_FSINCON fs inconsistencies, $N_DEVCNT device-counter errors, $lost lost-write errors, $kio I/O errors, $N_UNREADABLE unreadable sectors"
    (( ${#SKIPPED[@]} )) && VERDICT_LINE+=" [incomplete: ${#SKIPPED[@]} checks skipped]"
    printf '\nVERDICT: %s\nRECOMMENDATION: %s\nLOG: %s\n' "$VERDICT_LINE" "$V_REC" "$LOGFILE"
}

raw_appendix() {
    (( ${#RAW_FILES[@]} )) || return 0
    section "Raw tool output"
    local f
    for f in "${RAW_FILES[@]}"; do
        [[ -f $f ]] || continue
        printf '\n--- %s ---\n' "$(basename "$f" .txt | sed 's/^raw-[0-9]*-//')"
        head -n 400 "$f"
        (( $(wc -l <"$f") > 400 )) && echo "... (truncated, $(wc -l <"$f") lines)"
    done
}

# ----------------------------------------------------------------- flasher ---
# Reader number N whose READER_N by-path resolves to /dev/$DEV.
reader_number() {
    local n v
    for n in 1 2 3 4 5 6 7 8 9; do
        v=READER_$n; v=${!v:-}
        [[ -n $v && $(readlink -f "/dev/disk/by-path/$v" 2>/dev/null) == "/dev/$DEV" ]] && { echo "$n"; return 0; }
    done
    return 1
}
set_state() {  # set_state STATE MESSAGE
    [[ -n $READER ]] || return 0
    mkdir -p "$FLASH_STATE_DIR" 2>/dev/null
    printf '%s|%s|%s|%s\n' "$1" "$(date +%s)" "$DEV" "$2" >"$FLASH_STATE_DIR/$READER.tmp" 2>/dev/null &&
        mv -f "$FLASH_STATE_DIR/$READER.tmp" "$FLASH_STATE_DIR/$READER"
}
bmap_for_image() {
    local b
    for b in "$FLASHER_BMAP" "${FLASHER_IMAGE%.*}.bmap" "${FLASHER_IMAGE%.*.*}.bmap"; do
        [[ -n $b && -r $b ]] && { echo "$b"; return 0; }
    done
    return 1
}

# Read every mapped range back from the card and compare with the bmap
# checksums: catches cards that accept writes and then lose them.
# Returns 0 all match, 1 mismatches (count in VERIFY_BAD), 2 cannot verify.
verify_flash() {
    local bmap=$1 bs ctype sum start end n=0 bad=0 total got
    bs=$(sed -nE 's/.*<BlockSize>[[:space:]]*([0-9]+).*/\1/p' "$bmap" | head -1)
    ctype=$(sed -nE 's/.*<ChecksumType>[[:space:]]*([a-z0-9]+).*/\1/p' "$bmap" | head -1)
    ctype=${ctype:-sha1}
    { have "${ctype}sum" && [[ -n $bs ]]; } || { note "Cannot verify: unsupported bmap ($ctype)."; return 2; }
    sync; blockdev --flushbufs "/dev/$DEV" 2>/dev/null
    total=$(grep -c '<Range' "$bmap")
    note "Verifying $total mapped ranges by reading them back from the card..."
    while read -r sum start end; do
        end=${end:-$start}; n=$((n + 1))
        got=$("$DD" if="/dev/$DEV" bs="$bs" skip="$start" count=$(( end - start + 1 )) "${DDIN[@]}" status=none 2>/dev/null | "${ctype}sum" | cut -d' ' -f1)
        if [[ $got != "$sum" ]]; then
            bad=$((bad + 1))
            (( bad <= 5 )) && note "Mismatch in blocks $start-$end"
        fi
        (( n % 200 == 0 )) && set_state FLASH "Ověřuje zápis $(( n * 100 / total ))%"
    done < <(sed -nE 's/.*<Range[^>]*(chksum|sha1)="([0-9a-fA-F]+)"[^>]*>[[:space:]]*([0-9]+)(-([0-9]+))?[[:space:]]*<\/Range>.*/\2 \3 \5/p' "$bmap")
    VERIFY_BAD=$bad
    (( n > 0 )) || { note "Cannot verify: no ranges found in $bmap."; return 2; }
    (( bad == 0 )) && return 0
    return 1
}

flash_card() {
    section "Flashing (reader $READER)"
    local img=$FLASHER_IMAGE bmap="" rc
    [[ -r $img ]] || { set_state FAIL "CHYBA: obraz nenalezen ($img)"; finding 2 "Image not found: $img"; FLASH_RESULT=FAIL; return 1; }
    have bmaptool || { set_state FAIL "CHYBA: bmaptool není nainstalován"; finding 2 "bmaptool not installed"; FLASH_RESULT=FAIL; return 1; }
    [[ $(fingerprint) == "$FLASH_FP" ]] || { set_state FAIL "CHYBA: karta byla vyměněna"; finding 2 "Card changed during the check; not flashed"; FLASH_RESULT=FAIL; return 1; }
    local p m; m=$(mounted_parts)
    if [[ -n $m ]]; then
        while read -r p _; do umount "$p" 2>/dev/null; done <<<"$m"
        [[ -z $(mounted_parts) ]] || { set_state FAIL "CHYBA: karta je připojená (mount)"; finding 2 "Card is mounted; not flashed"; FLASH_RESULT=FAIL; return 1; }
    fi
    REMOUNT=()
    local args=(copy)
    if bmap=$(bmap_for_image); then args+=(--bmap "$bmap")
    else bmap=""; args+=(--nobmap); note "No .bmap found: copying the whole image (slow, no verification)."; fi
    kv "Image" "$img"
    kv "Bmap" "${bmap:-none}"
    set_state FLASH "Flashuje..."
    local log; rawfile bmaptool; log=$RAWF
    if (( FLASHER_DRYRUN )); then
        echo "DRY RUN: bmaptool ${args[*]} $img /dev/$DEV" | tee "$log"; sleep 3; rc=0
    else
        note "bmaptool ${args[*]} $img /dev/$DEV"
        bmaptool "${args[@]}" "$img" "/dev/$DEV" 2>&1 | tr '\r' '\n' | while IFS= read -r line; do
            printf '%s\n' "$line" >>"$log"
            [[ $line =~ ([0-9]+)% ]] && set_state FLASH "Flashuje ${BASH_REMATCH[1]}%"
        done
        rc=${PIPESTATUS[0]}
    fi
    kv "bmaptool exit code" "$rc"
    if (( rc != 0 )); then
        FLASH_RESULT=FAIL
        set_state FAIL "SELHALO – zápis se nepodařil → vyřadit"
        finding 2 "Flashing failed (bmaptool exit $rc): $(tail -1 "$log")" "The card could not be written: treat it as faulty."
        return 1
    fi
    if (( FLASHER_VERIFY && ! FLASHER_DRYRUN )) && [[ -n $bmap ]]; then
        set_state FLASH "Ověřuje zápis..."
        verify_flash "$bmap"; rc=$?
        if (( rc == 1 )); then
            FLASH_RESULT=FAIL
            set_state FAIL "VADNÁ – data po zápisu nesedí ($VERIFY_BAD úseků) → vyřadit"
            finding 2 "Verification failed: $VERIFY_BAD ranges read back differently from what was written" \
                "The card silently loses or corrupts writes (failing or fake card)."
            return 1
        elif (( rc == 0 )); then
            finding 0 "Verified: every written block reads back correctly"
        fi
    fi
    (( FLASHER_DRYRUN )) || blockdev --rereadpt "/dev/$DEV" 2>/dev/null
    FLASH_RESULT=DONE
    set_state DONE "HOTOVO$( (( FLASHER_DRYRUN )) && echo ' (zkušebně, nic nezapsáno)') – můžete vyndat kartu"
    finding 0 "Flashed $( (( FLASHER_DRYRUN )) && echo '(DRY RUN, nothing written) ')successfully"
}

# Decide what the flasher does with this card after the check.
flasher_step() {
    if (( V_LEVEL >= 2 )); then
        FLASH_RESULT=BAD
        set_state BAD "VADNÁ – vyřadit: $V_LABEL"
    elif (( V_LEVEL == 1 && ! FLASH_ON_WARNING )); then
        FLASH_RESULT=WARN
        set_state WARN "ZKONTROLOVAT – neflashováno: $V_LABEL"
    else
        flash_card
    fi
}

# --learn N [DEVICE]: remember which reader is number N.
learn_reader() {
    local n=${1:-} dev=${2:-} bp="" l d cands=()
    [[ $n =~ ^[1-9]$ ]] || { echo "$PROG: usage: --learn N [DEVICE], N = 1-9" >&2; exit 3; }
    (( EUID == 0 )) || { echo "$PROG: --learn needs root" >&2; exit 3; }
    if [[ -z $dev ]]; then
        for d in /sys/block/sd* /sys/block/mmcblk[0-9]; do
            [[ -e $d && $(readf "$d/size") != 0 ]] || continue
            DEV=${d##*/}
            reader_number >/dev/null && continue
            refuse_if_system_disk 2>/dev/null || continue
            cands+=("$DEV")
        done
        (( ${#cands[@]} == 1 )) || { echo "$PROG: put a card ONLY in reader $n (cards found in unnumbered readers: ${cands[*]:-none}), or name it: --learn $n sdX" >&2; exit 3; }
        dev=${cands[0]}
    else
        dev=$(resolve_dev "$dev") || exit 3
    fi
    for l in /dev/disk/by-path/*; do
        [[ $l == *-part* || $(readlink -f "$l") != "/dev/$dev" ]] && continue
        [[ -z $bp || $l != *usbv2* ]] && bp=${l##*/}
    done
    [[ -n $bp ]] || { echo "$PROG: /dev/$dev has no /dev/disk/by-path name" >&2; exit 3; }
    [[ -f $FLASHER_CONF ]] || printf '# sdcard-check flasher configuration\n' >"$FLASHER_CONF"
    if grep -q "^READER_$n=" "$FLASHER_CONF"; then
        sed -i "s|^READER_$n=.*|READER_$n=$bp|" "$FLASHER_CONF"
    else
        echo "READER_$n=$bp" >>"$FLASHER_CONF"
    fi
    echo "Redukce $n = $bp  (teď /dev/$dev). Uloženo do $FLASHER_CONF."
    exit 0
}

# --status: operator screen, refreshed every second.
status_screen() {
    trap 'printf "\033[0m\n"; exit 0' INT TERM
    local n v path st since dev msg col now name any el
    while :; do
        now=$(date +%s); any=0
        printf '\033[H\033[2J'
        printf '\033[1m  STANICE PRO FLASHOVÁNÍ SD KARET\033[0m      %s\n' "$(date '+%H:%M:%S')"
        printf '  obraz: %s%s\n\n' "${FLASHER_IMAGE:-(není nastaven – flashování vypnuto)}" "$( (( FLASHER_DRYRUN )) && echo '   [ZKUŠEBNÍ REŽIM – nic se nezapisuje]')"
        for n in 1 2 3 4 5 6 7 8 9; do
            v=READER_$n; v=${!v:-}; [[ -n $v ]] || continue; any=1
            path=/dev/disk/by-path/$v
            st="" since=$now dev="" msg=""
            [[ -r $FLASH_STATE_DIR/$n ]] && IFS='|' read -r st since dev msg <"$FLASH_STATE_DIR/$n"
            name=$(readlink -f "$path" 2>/dev/null); name=${name##*/}
            if [[ ! -e $path || $(readf "/sys/block/$name/size") == 0 ]]; then
                printf '  \033[1mREDUKCE %d\033[0m   \033[2m— prázdná —\033[0m\n\n' "$n"
                continue
            fi
            [[ $dev == "$name" ]] || { st=""; msg="čeká na kontrolu"; }
            case $st in
                DONE)     col='\033[1;42;30m' ;;
                BAD|FAIL) col='\033[1;41;37m' ;;
                WARN)     col='\033[1;43;30m' ;;
                *)        col='\033[1;46;30m' ;;
            esac
            el=""; [[ $st == CHECK || $st == FLASH ]] && el=$(printf '  (%d:%02d)' $(( (now - since) / 60 )) $(( (now - since) % 60 )))
            printf '  \033[1mREDUKCE %d\033[0m   %b %s \033[0m%s\n\n' "$n" "$col" "$msg" "$el"
        done
        (( any )) || printf '  Žádné redukce nejsou očíslované. Vložte kartu jen do redukce 1 a spusťte:\n    sudo sdcard-check.sh --learn 1\n\n'
        printf '  Ctrl+C = konec\n'
        sleep 1
    done
}

# --watch: wait for cards and check each one interactively in this terminal.
watch_loop() {
    (( EUID == 0 )) || { echo "$PROG: --watch needs root: sudo $0 --watch" >&2; exit 3; }
    ( : </dev/tty ) 2>/dev/null || { echo "$PROG: --watch needs a terminal" >&2; exit 3; }
    local sysd self d name fp rc
    sysd=$(system_disks | sort -u) || { echo "$PROG: cannot determine which disk holds /; refusing to operate" >&2; exit 3; }
    self=$(readlink -f "$0")
    if [[ -r $WATCH_PIDFILE ]] && kill -0 "$(<"$WATCH_PIDFILE")" 2>/dev/null; then
        echo "$PROG: another --watch is already running (pid $(<"$WATCH_PIDFILE"))" >&2; exit 3
    fi
    echo $$ >"$WATCH_PIDFILE"
    trap 'rm -f "$WATCH_PIDFILE"' EXIT
    trap 'echo; echo "Stopped watching. Automatic background checks are back on."; exit 0' INT TERM
    local -A seen=()
    printf '\033[1mWatching for SD cards and USB disks.\033[0m Insert a card. (Ctrl+C to stop)\n'
    while :; do
        # Forget cards that were removed, so re-inserting one checks it again.
        for name in "${!seen[@]}"; do
            [[ -e /sys/block/$name && $(readf "/sys/block/$name/size") != 0 ]] || unset "seen[$name]"
        done
        for d in /sys/block/sd* /sys/block/mmcblk[0-9]; do
            [[ -e $d ]] || continue
            name=${d##*/}
            [[ $(readf "$d/size") != 0 ]] || continue
            [[ $name == mmcblk* || $(readf "$d/removable") == 1 || $(lsblk -dno TRAN "/dev/$name" 2>/dev/null | tr -d ' ') == usb ]] || continue
            grep -qx -- "$name" <<<"$sysd" && continue
            fp="$(readf "$d/size")|$(readlink -f "$d/device")"
            [[ ${seen[$name]:-} == "$fp" ]] && continue
            seen[$name]=$fp
            sleep 2; udevadm settle -t 10 2>/dev/null     # let the partitions appear
            [[ -e $d ]] || continue
            printf '\n\a\033[1m>>> Card inserted: /dev/%s (%s)\033[0m\n' "$name" "$(human $(( $(readf "$d/size") * 512 )))"
            SDCARD_WATCH=1 "$self" "$name"; rc=$?
            printf '\n\033[1m>>> Finished /dev/%s (exit %d). Remove the card and insert the next one. (Ctrl+C to stop)\033[0m\n' "$name" "$rc"
        done
        sleep 1
    done
}

# The last thing printed: a plain answer to "is this card OK?".
final_block() {
    local n_csum=${#CSUM_KEYS[@]} n_bad=${#BADTREE_KEYS[@]}
    local lost=$(( ${#TRANSID_KEYS[@]} + N_SUPERGEN + N_ROLLBACK )) kio=$(( N_KIO + N_CARD_IO ))
    local total=$(( n_csum + n_bad + N_FSINCON + N_DEVCNT + lost + kio + N_UNREADABLE ))
    local word
    case $V_LEVEL in 0) word="GOOD" ;; 1) word="WARNING" ;; *) word="BAD" ;; esac
    local line='================================================================'
    printf '\n%s\n' "$line"
    printf '  RESULT: %s (%s)   %s/dev/%s  %s  %s\n' "$word" "$V_LABEL" "${READER:+reader $READER  }" "$DEV" "$(human "$SIZE_BYTES")" "$MODEL"
    printf '  Errors found: %d\n' "$total"
    printf '    checksum %d | bad tree blocks %d | fs inconsistencies %d | device counters %d\n' "$n_csum" "$n_bad" "$N_FSINCON" "$N_DEVCNT"
    printf '    lost writes %d | I/O errors %d | unreadable sectors %d\n' "$lost" "$kio" "$N_UNREADABLE"
    (( FLAG_RO ))   && printf '    card is READ-ONLY (locked itself)\n'
    (( FLAG_FAKE )) && printf '    FAKE CAPACITY detected\n'
    (( N_UNSTABLE )) && printf '    %d blocks return DIFFERENT data on each read (failing flash)\n' "$N_UNSTABLE"
    (( N_UNCLEAN )) && printf '  Note: not shut down cleanly last time it was used (%d signs). Always shut the Pi down before pulling power.\n' "$N_UNCLEAN"
    (( ${#SKIPPED[@]} )) && printf '  Note: %d checks skipped: %s\n' "${#SKIPPED[@]}" "${SKIPPED[*]}"
    (( ${#FINDINGS[@]} )) && printf '  Why: %s\n' "${FINDINGS[@]}"
    case $FLASH_RESULT in
        DONE) if (( FLASHER_DRYRUN )); then printf '  FLASH (reader %s): DRY RUN - would flash now, nothing was written\n' "$READER"
              else printf '  FLASH (reader %s): DONE - card flashed%s\n' "$READER" "$( (( FLASHER_VERIFY )) && echo ' and verified')"; fi ;;
        FAIL) printf '  FLASH (reader %s): FAILED - discard the card\n' "$READER" ;;
        BAD)  printf '  FLASH (reader %s): NOT FLASHED - card is faulty, discard it\n' "$READER" ;;
        WARN) printf '  FLASH (reader %s): NOT FLASHED - check the card (FLASH_ON_WARNING=0)\n' "$READER" ;;
    esac
    printf '  What to do: %s\n' "$V_REC"
    (( ${#MOUNTED_MSGS[@]} )) && printf '  Mounted: %s\n' "${MOUNTED_MSGS[*]}"
    printf '  Full log: %s\n' "$LOGFILE"
    printf '%s\n' "$line"
}

# Manual runs with WARNING/BAD: offer the full read scan right away.
offer_full_scan() {
    (( ! MODE_UDEV && ! MODE_FULL && V_LEVEL >= 1 )) || return 0
    ( : </dev/tty ) 2>/dev/null || return 0
    [[ -e $SYS ]] || return 0
    local mins=$(( SIZE_BYTES / (20 * 1024 * 1024) / 60 + 1 )) ans
    printf '\nErrors or warnings were found. Run a full read scan of every sector now (about %d min)? [y/N] ' "$mins" >/dev/tty
    read -r ans </dev/tty || ans=""
    echo "Full read scan offered; answer: ${ans:-no}"
    [[ $ans == [yYaA]* ]] || return 0
    MODE_FULL=1
    full_scan
    # Re-grade with the scan included and print a fresh result box.
    V_LEVEL=0 V_LABEL=CLEAN V_REC="No problems found; the card looks healthy."
    summarize >/dev/null
    final_block
}

# Desktop notification for every active graphical session (via loginctl).
notify_users() {
    (( NOTIFY )) || return 0
    have notify-send || { note "notify-send not installed; no desktop notification."; return 0; }
    local title=$1 body=$2 urgency=$3
    local args=(-a "$PROG" -u "$urgency" -i drive-removable-media "$title" "$body")
    if (( EUID != 0 )); then notify-send "${args[@]}" 2>/dev/null; return 0; fi
    local name uid bus
    while read -r name uid; do
        bus=/run/user/$uid/bus
        [[ -S $bus ]] || continue
        # Run notify-send inside the user's own session (systemd --user):
        # from this sandboxed service, AppArmor denies a direct connection
        # to the user's bus ("disconnected path").
        if have systemd-run && systemd-run --user --machine="$name@.host" --quiet --collect \
                notify-send "${args[@]}" 2>/dev/null; then
            note "Notified $name."
        elif setpriv --reuid="$uid" --regid="$(id -g "$name")" --init-groups \
                env DBUS_SESSION_BUS_ADDRESS="unix:path=$bus" XDG_RUNTIME_DIR="/run/user/$uid" \
                notify-send "${args[@]}" 2>/dev/null; then
            note "Notified $name."
        else
            note "Could not send a desktop notification to $name."
        fi
    done < <(graphical_users)
}

# Debian/Ubuntu/Raspberry Pi OS: install every tool the checks use.
DEPS=(btrfs-progs e2fsprogs dosfstools f3 util-linux smartmontools libnotify-bin mmc-utils bmaptool zstd)
install_deps() {
    (( EUID == 0 )) || { echo "$PROG: --install-deps needs root: sudo $0 --install-deps" >&2; exit 3; }
    have apt-get || { echo "$PROG: apt-get not found; install these with your package manager: ${DEPS[*]}" >&2; exit 3; }
    # --no-install-recommends keeps smartmontools from pulling in a mail server.
    apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends "${DEPS[@]}" || exit 3
    local t missing=()
    for t in btrfs e2fsck dumpe2fs debugfs fsck.fat f3probe badblocks smartctl notify-send mmc lsblk blkid findmnt bmaptool zstd; do
        have "$t" || missing+=("$t")
    done
    (( ${#missing[@]} )) && { echo "$PROG: still missing: ${missing[*]}" >&2; exit 3; }
    echo "$PROG: all dependencies installed."
    exit 0
}

# ------------------------------------------------------------------- main ---
on_exit() {
    local rc=$?
    (( ${#REMOUNT[@]} )) && finish_mounts
    [[ -n $WORK ]] && rm -rf "$WORK"
    if (( ! DONE )); then
        echo "$PROG: aborted unexpectedly (exit $rc)" >&2
        exit 3
    fi
}

run() {
    trap on_exit EXIT
    trap 'echo "$PROG: interrupted (device removed?)" >&2; DONE=1; exit 3' TERM INT HUP
    WORK=$(mktemp -d "${TMPDIR:-/tmp}/$PROG.XXXXXX") || die "cannot create temp dir"

    echo "$PROG on /dev/$DEV  $(date -Is)  mode: $( (( MODE_UDEV )) && echo udev || echo manual)$( (( MODE_FULL )) && echo ' +full')$( (( MODE_DESTRUCTIVE )) && echo ' +destructive')"
    (( EUID == 0 )) || echo "Note: not running as root; some checks may be unavailable."

    if (( MODE_FULL || MODE_DESTRUCTIVE )); then
        (( MODE_UDEV )) && die "--full and --destructive are manual-only and never run from udev"
        (( PPID == 1 )) && die "--full and --destructive must be run by hand from a terminal"
        ( : </dev/tty ) 2>/dev/null || die "--full and --destructive need an interactive terminal"
    fi
    (( MODE_DESTRUCTIVE )) && confirm_destructive
    (( MODE_UDEV && ! FLASHER )) && notify_users "Checking /dev/$DEV..." "SD/USB health check started; the card is mounted when it finishes." low

    device_facts
    if [[ -n $FLASHER_IMAGE ]] && READER=$(reader_number); then
        FLASHER=1; AUTOMOUNT_AFTER=0; FLASH_FP=$(fingerprint)
        kv "Flasher reader" "$READER (image $FLASHER_IMAGE)"
        set_state CHECK "Kontrola karty..."
    fi
    # Only a real I/O error is a bad sector. Permission problems and
    # O_DIRECT being rejected are problems with how we read, not the card.
    if ! "$DD" if="/dev/$DEV" of=/dev/null bs=4096 count=1 "${DDIN[@]}" status=none 2>"$WORK/open.err"; then
        grep -q 'Permission denied' "$WORK/open.err" && die "cannot read /dev/$DEV (permission denied); run as root"
        if ! grep -qE "$RE_MEDIA_ERR" "$WORK/open.err" &&
           "$DD" if="/dev/$DEV" of=/dev/null bs=4096 count=1 status=none 2>/dev/null; then
            DDIN=()
            note "Direct I/O rejected by this device/reader ($(<"$WORK/open.err")); using buffered reads."
        elif grep -qE "$RE_MEDIA_ERR" "$WORK/open.err"; then
            finding 2 "The first block of /dev/$DEV cannot be read: $(<"$WORK/open.err")" "Physical failure (or the card dropped off the bus)."
            N_UNREADABLE=$(( N_UNREADABLE + 4096 / LBS ))
        else
            die "cannot read /dev/$DEV with $DD: $(<"$WORK/open.err")"
        fi
    fi
    kv "Reader" "$DD ${DDIN[*]:-(buffered)}"
    write_protect_checks
    emmc_health
    smart_health
    kernel_checks
    power_checks
    partition_checks
    fake_capacity_probe
    (( MODE_FULL )) && full_scan
    (( MODE_DESTRUCTIVE )) && destructive_test

    summarize
    if (( FLASHER )); then
        flasher_step
        [[ $FLASH_RESULT == FAIL ]] && V_LEVEL=2
    fi
    finish_mounts
    # Raw tool output goes to its own file so it never buries the result.
    raw_appendix >"${LOGFILE%.log}.raw.txt" 2>&1
    echo "Raw tool output: ${LOGFILE%.log}.raw.txt"
    final_block
    local urg=low; (( V_LEVEL == 1 )) && urg=normal; (( V_LEVEL == 2 )) && urg=critical
    local title="SD check: $V_LABEL (/dev/$DEV)"
    case $FLASH_RESULT in
        DONE) title="Redukce $READER: HOTOVO"; urg=normal ;;
        FAIL) title="Redukce $READER: SELHALO – vyřadit kartu"; urg=critical ;;
        BAD)  title="Redukce $READER: VADNÁ karta – vyřadit"; urg=critical ;;
        WARN) title="Redukce $READER: ZKONTROLOVAT kartu"; urg=critical ;;
    esac
    notify_users "$title" "$VERDICT_LINE"$'\n'"$V_REC"$'\n'"${MOUNTED_MSGS[*]:+Mounted: ${MOUNTED_MSGS[*]}}"$'\n'"Log: $LOGFILE" "$urg"

    offer_full_scan
    DONE=1
    exit "$V_LEVEL"
}

entry() {
    local arg target=""
    for arg in "$@"; do
        case $arg in
            --full)           MODE_FULL=1 ;;
            --destructive)    MODE_DESTRUCTIVE=1 ;;
            --udev)           MODE_UDEV=1 ;;
            --check-eligible) MODE_ELIGIBLE=1 ;;
            --no-notify)      NOTIFY=0 ;;
            --no-unmount)     AUTO_UNMOUNT=0 ;;
            --install-deps)   install_deps ;;
            --track)          MODE_TRACK=1 ;;
            --status)         status_screen ;;
            --watch)          watch_loop ;;
            --learn)          shift; learn_reader "$@" ;;
            -h|--help)        usage; exit 0 ;;
            -*)               echo "$PROG: unknown option $arg" >&2; usage >&2; exit 3 ;;
            *)                [[ -z $target ]] || { echo "$PROG: only one device at a time" >&2; exit 3; }; target=$arg ;;
        esac
    done
    if [[ -z $target ]]; then
        # No device named: use the only removable card that has media in it.
        local d c=()
        for d in /sys/block/sd* /sys/block/mmcblk[0-9]; do
            [[ -e $d && $(readf "$d/size") != 0 && $(readf "$d/removable") == 1 || -e $d && $d == */mmcblk* && $(readf "$d/size") != 0 ]] || continue
            DEV=${d##*/}; refuse_if_system_disk 2>/dev/null || continue
            c+=("$DEV")
        done
        if (( ${#c[@]} == 1 )); then
            target=${c[0]}
            echo "Using /dev/$target ($(human $(( $(readf "/sys/block/$target/size") * 512 ))) $(lsblk -dno TRAN "/dev/$target" 2>/dev/null | tr -d ' '))"
        elif (( ${#c[@]} == 0 )); then
            echo "$PROG: no SD card or USB disk with media found" >&2; exit 3
        else
            echo "$PROG: several cards are inserted; name one:" >&2
            for d in "${c[@]}"; do echo "  sudo $0 $d    ($(human $(( $(readf "/sys/block/$d/size") * 512 ))))" >&2; done
            exit 3
        fi
    fi
    DEV=$(resolve_dev "$target") || exit 3
    SYS=/sys/block/$DEV

    # Hard refusal: never touch the disk the system runs from.
    if ! refuse_if_system_disk; then
        (( MODE_ELIGIBLE )) && exit 1
        exit 3
    fi
    if (( MODE_ELIGIBLE && MODE_UDEV )) && [[ -r $WATCH_PIDFILE ]] && kill -0 "$(<"$WATCH_PIDFILE")" 2>/dev/null; then
        echo "/dev/$DEV is handled by the running 'sdcard-check.sh --watch'" >&2; exit 1
    fi
    if (( MODE_ELIGIBLE )); then
        [[ $(readf "$SYS/size") != 0 ]] || { echo "/dev/$DEV has no medium" >&2; exit 1; }
        exit 0
    fi
    (( MODE_TRACK )) && track

    mkdir -p "$LOG_DIR" 2>/dev/null
    if [[ ! -w $LOG_DIR ]]; then
        LOG_DIR=${XDG_STATE_HOME:-$HOME/.local/state}/$PROG
        mkdir -p "$LOG_DIR" || exit 3
    fi
    LOGFILE=$LOG_DIR/$DEV-$(date +%Y%m%d-%H%M%S).log

    # Run niced when started by hand (the systemd unit sets this itself).
    if [[ -z ${INVOCATION_ID:-} ]] || (( ! MODE_UDEV )); then
        renice -n 10 -p $$ >/dev/null 2>&1
        ionice -c 3 -p $$ >/dev/null 2>&1
    fi

    run 2>&1 | tee -a "$LOGFILE"
    exit "${PIPESTATUS[0]}"
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    entry "$@"
fi
