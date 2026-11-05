#!/bin/sh
# sshole-scan.sh -- fan the read-only probe out over many hosts and report.
#
# Changes nothing anywhere. Writes only to its own output directory locally.
#
# Usage:
#   sshole-scan.sh [options] [host ...]
#   sshole-scan.sh --hosts-file hosts.txt
#
# Options:
#   --hosts-file F   one host per line ("#" comments, blank lines ignored);
#                    a line may be "user@host" or "host" or "host  # label"
#   --out DIR        output directory (default ./sshole-reports/<UTC stamp>)
#   --user U         default SSH user when a host line does not carry one
#   --sudo           run the probe under `sudo -n` (default: auto -- plain
#                    when the SSH user is root, sudo otherwise)
#   --no-sudo        never use sudo
#   --no-containers  skip the Docker container pass on each host
#   --timeout N      SSH connect timeout, seconds (default 20)
#   --jobs N         how many hosts to probe at once (default 5)
#   --probe PATH     path to sshole-probe.sh (default: alongside this script)
#
# Exit status: 0 = every host probed and none vulnerable; 1 = at least one
# host is vulnerable or needs a restart; 2 = usage error; 3 = a host could
# not be probed (and nothing vulnerable was found among those that could).

set -u

SELF_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
PROBE="$SELF_DIR/sshole-probe.sh"
HOSTS_FILE=""
OUT=""
SSH_USER=""
SUDO_MODE=auto
PROBE_ARGS=""
TIMEOUT=20
JOBS=5
HOSTS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --hosts-file) HOSTS_FILE="${2:?--hosts-file needs a path}"; shift ;;
    --out) OUT="${2:?--out needs a path}"; shift ;;
    --user) SSH_USER="${2:?--user needs a name}"; shift ;;
    --sudo) SUDO_MODE=yes ;;
    --no-sudo) SUDO_MODE=no ;;
    --no-containers) PROBE_ARGS="$PROBE_ARGS --no-containers" ;;
    --timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift ;;
    --jobs) JOBS="${2:?--jobs needs a number}"; shift ;;
    --probe) PROBE="${2:?--probe needs a path}"; shift ;;
    -h|--help) sed -n '2,30p' "$0"; exit 0 ;;
    -*) echo "sshole-scan: unknown option: $1" >&2; exit 2 ;;
    *) HOSTS="$HOSTS$1
" ;;
  esac
  shift
done

[ -r "$PROBE" ] || { echo "sshole-scan: probe not found: $PROBE" >&2; exit 2; }

if [ -n "$HOSTS_FILE" ]; then
  [ -r "$HOSTS_FILE" ] || { echo "sshole-scan: cannot read $HOSTS_FILE" >&2; exit 2; }
  HOSTS="$HOSTS$(sed -e 's/#.*//' -e 's/[[:space:]]*$//' -e '/^$/d' "$HOSTS_FILE")
"
fi

HOSTS="$(printf '%s' "$HOSTS" | sed '/^$/d' | awk '!seen[$0]++')"
[ -n "$HOSTS" ] || { echo "sshole-scan: no hosts given (pass hosts or --hosts-file)" >&2; exit 2; }

[ -n "$OUT" ] || OUT="$PWD/sshole-reports/$(date -u '+%Y%m%dT%H%M%SZ')"
mkdir -p "$OUT" || { echo "sshole-scan: cannot create $OUT" >&2; exit 2; }

echo "sshole-scan: $(printf '%s' "$HOSTS" | wc -l | tr -d ' ') host(s) -> $OUT"

probe_one() {
  target="$1"
  safe="$(printf '%s' "$target" | tr -c 'A-Za-z0-9._@-' '_')"
  jsonf="$OUT/$safe.json"
  errf="$OUT/$safe.err"
  case "$target" in *@*) u="${target%%@*}" ;; *) u="$SSH_USER" ;; esac
  dest="$target"
  [ -n "$SSH_USER" ] && case "$target" in *@*) : ;; *) dest="$SSH_USER@$target" ;; esac

  # Decide how to get root on the far side.
  eff_user="$u"
  [ -n "$eff_user" ] || eff_user="$(ssh -G "$target" 2>/dev/null | awk '$1=="user"{print $2; exit}')"
  case "$SUDO_MODE" in
    yes) remote="sudo -n sh -s --" ;;
    no)  remote="sh -s --" ;;
    *)   if [ "$eff_user" = root ]; then remote="sh -s --"; else remote="sudo -n sh -s --"; fi ;;
  esac

  if ! ssh -o BatchMode=yes -o ConnectTimeout="$TIMEOUT" -o StrictHostKeyChecking=accept-new \
        "$dest" "$remote --json $PROBE_ARGS" < "$PROBE" > "$jsonf" 2> "$errf"; then
    # One retry without sudo: the box may already log us in as root, or sudo
    # may need a password (in which case we still want the degraded answer).
    if [ "$remote" != "sh -s --" ]; then
      ssh -o BatchMode=yes -o ConnectTimeout="$TIMEOUT" -o StrictHostKeyChecking=accept-new \
        "$dest" "sh -s -- --json $PROBE_ARGS" < "$PROBE" > "$jsonf" 2>> "$errf" || true
    fi
  fi
  if [ -s "$jsonf" ]; then
    printf '%s\n' "$target" > "$OUT/$safe.target"
  else
    printf 'unreachable\n' > "$OUT/$safe.unreachable"
  fi
}

# Bounded parallelism without any bashisms.
running=0
for h in $HOSTS; do
  probe_one "$h" &
  running=$((running + 1))
  if [ "$running" -ge "$JOBS" ]; then wait; running=0; fi
done
wait

# ------------------------------------------------------------------ report

REPORT="$OUT/report.txt"
VULN=0
FAILED=0
: > "$REPORT"

emit() { printf '%s\n' "$1" >> "$REPORT"; }
emit "*sshole scan -- $(date -u '+%Y-%m-%d %H:%M:%SZ')"
emit "probe: $PROBE"
emit ""

have_jq=0
command -v jq >/dev/null 2>&1 && have_jq=1

for h in $HOSTS; do
  safe="$(printf '%s' "$h" | tr -c 'A-Za-z0-9._@-' '_')"
  jsonf="$OUT/$safe.json"
  if [ ! -s "$jsonf" ]; then
    emit "[UNREACHABLE] $h"
    emit "    $(head -2 "$OUT/$safe.err" 2>/dev/null | tr '\n' ' ')"
    FAILED=1
    continue
  fi
  if [ $have_jq -eq 1 ]; then
    if ! jq -e . "$jsonf" >/dev/null 2>&1; then
      emit "[BAD OUTPUT] $h -- probe output was not valid JSON (see $jsonf)"
      FAILED=1
      continue
    fi
    state="$(jq -r '.verdict.state' "$jsonf")"
    sev="$(jq -r '.verdict.severity // "?"' "$jsonf")"
    conf="$(jq -r '.verdict.confidence // "?"' "$jsonf")"
    emit "[$(printf '%s' "$state" | tr 'a-z' 'A-Z')] $h   (severity $sev, confidence $conf)"
    jq -r '"    os: \(.target.pretty // .target.os_id // "?")   sshd: \(.sshd.version // "?")   libc: \(.sshd.libc // "?")"' "$jsonf" >> "$REPORT"
    jq -r '"    pam: linked=\(.sshd.pam_linked) active=\(.sshd.pam_active)   passwordauth: \(.config.passwordauthentication // "?")   patch: \(.patch.status // "?")\(if .patch.required != "" and .patch.required != null then " (need >= " + .patch.required + ")" else "" end)"' "$jsonf" >> "$REPORT"
    jq -r '"    \"*\" accounts: \(.accounts.star_count)   reachable: \(.accounts.exploitable | join(",") | if . == "" then "none" else . end)   salt donors: \(.accounts.salt_donors_sha)"' "$jsonf" >> "$REPORT"
    jq -r '.verdict.reasons[]? | "      - " + .' "$jsonf" >> "$REPORT"
    n="$(jq -r '.compromise.suspicious_accept_count // 0' "$jsonf")"
    if [ "$n" != "0" ] && [ "$n" != "null" ]; then
      emit "    !! $n password login(s) accepted for a \"*\" account -- treat as compromised:"
      jq -r '.compromise.suspicious_accepts[]? | "      ! " + .' "$jsonf" >> "$REPORT"
    fi
    jq -r '.containers.list[]? | select(.runs_sshd == true) | "    container running sshd: \(.name) [\(.image)] libc=\(.libc) port22=\(.port_22_published) verdict=\(.verdict)"' "$jsonf" >> "$REPORT"
    jq -r '.notes[]? | "    note: " + .' "$jsonf" >> "$REPORT"
    case "$state" in vulnerable|needs_restart) VULN=1 ;; unknown) FAILED=1 ;; esac
  else
    state="$(sed -n 's/.*"state": *"\([a-z_]*\)".*/\1/p' "$jsonf" | head -1)"
    emit "[${state:-UNKNOWN}] $h   (install jq for the detailed report)"
    case "$state" in vulnerable|needs_restart) VULN=1 ;; esac
  fi
  emit ""
done

if [ $have_jq -eq 1 ]; then
  for f in "$OUT"/*.json; do [ -e "$f" ] && jq -c . "$f" 2>/dev/null; done > "$OUT/all.jsonl"
fi

emit "---"
if [ $VULN -eq 1 ]; then
  emit "ACTION REQUIRED: at least one host is exploitable. Remediate with:"
  emit "  sshole-fix.sh --host <host> --mode upgrade     # apk upgrade openssh + restart sshd"
  emit "  sshole-fix.sh --host <host> --mode mitigate    # PasswordAuthentication no (check keys first!)"
else
  emit "No host came back vulnerable."
fi
[ $FAILED -eq 1 ] && emit "Some hosts could not be probed or returned an indeterminate result -- see above."

cat "$REPORT"
echo ""
echo "raw json: $OUT/"
[ $VULN -eq 1 ] && exit 1
[ $FAILED -eq 1 ] && exit 3
exit 0
