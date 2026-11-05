#!/bin/sh
# sshole-fix.sh -- remediate the *sshole sshd password bypass on one host.
#
# DRY RUN BY DEFAULT. Nothing is changed until you pass --yes.
#
# Usage:
#   sshole-fix.sh --host HOST [--mode auto|upgrade|mitigate|both|revert-mitigation]
#                 [--yes] [--user U] [--no-sudo] [--all-packages]
#                 [--accept-password-login-loss] [--force] [--timeout N]
#
# Modes:
#   auto      (default) upgrade if a fixed package is reachable, else mitigate
#   upgrade   apk/apt upgrade the openssh packages, then restart sshd
#   mitigate  set PasswordAuthentication no, then restart sshd
#   both      mitigate first (instant), then upgrade
#   revert-mitigation   undo what mitigate did
#
# Safety:
#   * every edited file is backed up to <file>.sshole-<stamp>, and the exact
#     revert command is printed
#   * `sshd -t` must pass before any restart; if it fails the change is rolled
#     back and nothing is restarted
#   * after the restart the effective config and version are re-read, and the
#     caller is told to verify a fresh login BEFORE closing its session
#   * mitigate refuses to run if an account has a real password hash but no
#     authorized_keys (that account would lose its only way in) unless you
#     pass --accept-password-login-loss
#   * a glibc host is left alone unless you pass --force

set -u

HOST=""
MODE=auto
ASSUME_YES=0
SSH_USER=""
USE_SUDO=auto
ALL_PACKAGES=0
ACCEPT_PW_LOSS=0
FORCE=0
TIMEOUT=20

while [ $# -gt 0 ]; do
  case "$1" in
    --host) HOST="${2:?--host needs a value}"; shift ;;
    --mode) MODE="${2:?--mode needs a value}"; shift ;;
    --yes|-y) ASSUME_YES=1 ;;
    --user) SSH_USER="${2:?--user needs a value}"; shift ;;
    --no-sudo) USE_SUDO=no ;;
    --sudo) USE_SUDO=yes ;;
    --all-packages) ALL_PACKAGES=1 ;;
    --accept-password-login-loss) ACCEPT_PW_LOSS=1 ;;
    --force) FORCE=1 ;;
    --timeout) TIMEOUT="${2:?--timeout needs seconds}"; shift ;;
    -h|--help) sed -n '2,32p' "$0"; exit 0 ;;
    *) echo "sshole-fix: unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

[ -n "$HOST" ] || { echo "sshole-fix: --host is required" >&2; exit 2; }
case "$MODE" in auto|upgrade|mitigate|both|revert-mitigation) : ;;
  *) echo "sshole-fix: bad --mode: $MODE" >&2; exit 2 ;; esac

DEST="$HOST"
[ -n "$SSH_USER" ] && case "$HOST" in *@*) : ;; *) DEST="$SSH_USER@$HOST" ;; esac
EFF_USER="$(ssh -G "$HOST" 2>/dev/null | awk '$1=="user"{print $2; exit}')"
case "$HOST" in *@*) EFF_USER="${HOST%%@*}" ;; esac
case "$USE_SUDO" in
  yes) PRIV="sudo -n" ;;
  no)  PRIV="" ;;
  *)   if [ "$EFF_USER" = root ]; then PRIV=""; else PRIV="sudo -n"; fi ;;
esac

DRY=1
[ $ASSUME_YES -eq 1 ] && DRY=0

echo "sshole-fix: host=$DEST mode=$MODE $( [ $DRY -eq 1 ] && echo '(DRY RUN -- pass --yes to apply)' || echo '(APPLYING)')"

# The remote half. Reads its settings from argv so this file stays the single
# source of truth; prints a PLAN/DONE transcript that the caller just relays.
REMOTE_SCRIPT='
set -u
MODE="$1"; DRY="$2"; ALL_PACKAGES="$3"; ACCEPT_PW_LOSS="$4"; FORCE="$5"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
say() { printf "%s\n" "$*"; }
run() {
  if [ "$DRY" = 1 ]; then say "  would run: $*"; return 0; fi
  say "  running:   $*"
  "$@"
}

[ "$(id -u)" = 0 ] || { say "FATAL: not root on the remote host (need root to edit sshd config / upgrade packages)"; exit 11; }

SSHD_BIN=""
for c in /usr/sbin/sshd /usr/bin/sshd /sbin/sshd; do [ -x "$c" ] && { SSHD_BIN="$c"; break; }; done
[ -n "$SSHD_BIN" ] || { say "FATAL: no sshd binary found"; exit 12; }

# ---- facts
LIBC=unknown
if command -v ldd >/dev/null 2>&1; then
  case "$(ldd "$SSHD_BIN" 2>/dev/null)" in
    *ld-musl*|*libc.musl*) LIBC=musl ;;
    *libc.so.6*|*ld-linux*) LIBC=glibc ;;
  esac
fi
if [ "$LIBC" = unknown ]; then
  for g in /lib/ld-musl-*.so.1; do [ -e "$g" ] && LIBC=musl; done
fi
VER="$( { "$SSHD_BIN" -V 2>&1; "$SSHD_BIN" -\? 2>&1; } | grep -m1 -o "OpenSSH_[0-9][^ ,]*")"
PWAUTH="$("$SSHD_BIN" -T 2>/dev/null | awk "tolower(\$1)==\"passwordauthentication\"{print \$2; exit}")"
say "remote facts: libc=$LIBC sshd=$VER passwordauthentication=${PWAUTH:-unknown}"

if [ "$LIBC" != musl ] && [ "$FORCE" != 1 ]; then
  say "SKIP: this host is $LIBC, which is not affected by *sshole. Nothing to do."
  say "      (pass --force if you want the change applied anyway.)"
  exit 0
fi

# ---- restart command
RESTART=""
if command -v rc-service >/dev/null 2>&1 && rc-service --exists sshd 2>/dev/null; then
  RESTART="rc-service sshd restart"
elif command -v systemctl >/dev/null 2>&1; then
  for u in sshd ssh; do
    if systemctl list-unit-files "$u.service" >/dev/null 2>&1 && systemctl cat "$u.service" >/dev/null 2>&1; then
      RESTART="systemctl restart $u.service"; SSH_UNIT="$u"; break
    fi
  done
elif [ -x /etc/init.d/sshd ]; then RESTART="/etc/init.d/sshd restart"
elif [ -x /etc/init.d/ssh ]; then RESTART="/etc/init.d/ssh restart"
fi
[ -n "$RESTART" ] || say "WARNING: could not work out how to restart sshd; you will have to restart it yourself."

validate_then_restart() {
  say "validating sshd config before restarting"
  if [ "$DRY" = 1 ]; then
    if "$SSHD_BIN" -t 2>&1; then say "  sshd -t: OK (current config)"; fi
    say "  would run: $RESTART"
    return 0
  fi
  if ! "$SSHD_BIN" -t 2>&1; then
    say "FATAL: sshd -t rejected the new config. Rolling back and NOT restarting."
    return 1
  fi
  say "  sshd -t: OK"
  [ -n "$RESTART" ] && { say "  running:   $RESTART"; $RESTART; }
  if command -v systemctl >/dev/null 2>&1 && [ -n "${SSH_UNIT:-}" ]; then
    if systemctl is-active "$SSH_UNIT.socket" >/dev/null 2>&1; then
      say "  running:   systemctl restart $SSH_UNIT.socket  (socket-activated)"
      systemctl restart "$SSH_UNIT.socket"
    fi
  fi
  return 0
}

# ---- mitigate: PasswordAuthentication no
do_mitigate() {
  say ""
  say "== mitigate: PasswordAuthentication no"
  # Lockout guard: an account with a real hash and no authorized_keys loses
  # its only way in when password auth goes away.
  AT_RISK=""
  while IFS=: read -r u h rest; do
    case "$h" in
      \$*)
        home="$(awk -F: -v u="$u" "\$1==u{print \$6}" /etc/passwd)"
        [ -n "$home" ] || continue
        [ -s "$home/.ssh/authorized_keys" ] || AT_RISK="$AT_RISK $u"
        ;;
    esac
  done < /etc/shadow
  if [ -n "$AT_RISK" ]; then
    say "  NOTE: these accounts have a real password but no authorized_keys, so"
    say "        password login is their only way in:$AT_RISK"
    if [ "$ACCEPT_PW_LOSS" != 1 ]; then
      say "  REFUSING to disable password auth. Install keys for those accounts first,"
      say "  or re-run with --accept-password-login-loss if you are sure."
      return 20
    fi
    say "  --accept-password-login-loss given; continuing."
  fi

  DROPIN=/etc/ssh/sshd_config.d/00-sshole-no-passwords.conf
  run mkdir -p /etc/ssh/sshd_config.d
  if [ "$DRY" = 1 ]; then
    say "  would write: $DROPIN  <- \"PasswordAuthentication no\""
  else
    printf "# Added by sshole-fix %s: mitigation for the *sshole bypass.\n# Remove this file (and the backup swap below) to allow password logins again.\nPasswordAuthentication no\nKbdInteractiveAuthentication no\n" "$STAMP" > "$DROPIN"
    say "  wrote:     $DROPIN"
  fi
  # Alpine < 3.19 ships an sshd_config with no Include line, so the drop-in
  # would be ignored. Edit the main file too, keeping a backup.
  if ! grep -qiE "^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/" /etc/ssh/sshd_config 2>/dev/null; then
    say "  main sshd_config has no Include for sshd_config.d -- editing it directly"
    if [ "$DRY" = 1 ]; then
      say "  would back up /etc/ssh/sshd_config -> /etc/ssh/sshd_config.sshole-$STAMP"
      say "  would set PasswordAuthentication no in /etc/ssh/sshd_config"
    else
      cp -p /etc/ssh/sshd_config "/etc/ssh/sshd_config.sshole-$STAMP"
      sed -i -e "s/^\([[:space:]]*#\?[[:space:]]*PasswordAuthentication[[:space:]][[:space:]]*\)yes/\1no/I" /etc/ssh/sshd_config
      grep -qiE "^[[:space:]]*PasswordAuthentication[[:space:]]+no" /etc/ssh/sshd_config ||
        sed -i "1i PasswordAuthentication no" /etc/ssh/sshd_config
      say "  edited:    /etc/ssh/sshd_config (backup: /etc/ssh/sshd_config.sshole-$STAMP)"
    fi
  fi
  if ! validate_then_restart; then
    if [ "$DRY" != 1 ]; then
      rm -f "$DROPIN"
      [ -f "/etc/ssh/sshd_config.sshole-$STAMP" ] && mv "/etc/ssh/sshd_config.sshole-$STAMP" /etc/ssh/sshd_config
      say "  rolled back."
    fi
    return 21
  fi
  if [ "$DRY" != 1 ]; then
    NOW="$("$SSHD_BIN" -T 2>/dev/null | awk "tolower(\$1)==\"passwordauthentication\"{print \$2; exit}")"
    say "  effective passwordauthentication is now: ${NOW:-unknown}"
    [ "$NOW" = no ] || { say "  WARNING: still not \"no\" -- check for a Match block that re-enables it."; return 22; }
  fi
  say "  revert with: sshole-fix.sh --host <host> --mode revert-mitigation --yes"
  return 0
}

do_revert_mitigation() {
  say ""
  say "== revert mitigation"
  DROPIN=/etc/ssh/sshd_config.d/00-sshole-no-passwords.conf
  [ -e "$DROPIN" ] && run rm -f "$DROPIN" || say "  (no drop-in to remove)"
  BK="$(ls -1t /etc/ssh/sshd_config.sshole-* 2>/dev/null | head -1)"
  if [ -n "$BK" ]; then
    run cp -p "$BK" /etc/ssh/sshd_config
    say "  restored from $BK"
  else
    say "  (no sshd_config backup found; main file untouched)"
  fi
  validate_then_restart || return 21
  return 0
}

# ---- upgrade
do_upgrade() {
  say ""
  say "== upgrade openssh"
  if command -v apk >/dev/null 2>&1; then
    PKGS="$(apk info 2>/dev/null | grep -x "openssh.*" | tr "\n" " ")"
    say "  installed openssh packages: ${PKGS:-none}"
    BEFORE="$(apk info -v 2>/dev/null | grep -m1 "^openssh-server" || apk info -v 2>/dev/null | grep -m1 "^openssh-")"
    if [ "$ALL_PACKAGES" = 1 ]; then
      run apk upgrade -U -a
    else
      run apk update
      # shellcheck disable=SC2086
      if [ -n "$PKGS" ]; then run apk upgrade $PKGS; else run apk upgrade openssh; fi
    fi
    AFTER="$(apk info -v 2>/dev/null | grep -m1 "^openssh-server" || apk info -v 2>/dev/null | grep -m1 "^openssh-")"
    say "  openssh: ${BEFORE:-?}  ->  ${AFTER:-?}"
    if [ "$DRY" != 1 ] && [ "$BEFORE" = "$AFTER" ]; then
      say "  WARNING: the package version did not change. Either it was already current,"
      say "  or this box pins an Alpine branch whose repositories no longer carry the fix."
      say "  Check /etc/apk/repositories, then fall back to --mode mitigate."
    fi
  elif command -v apt-get >/dev/null 2>&1; then
    BEFORE="$(dpkg-query -W -f="\${Version}" openssh-server 2>/dev/null)"
    run apt-get update
    DEBIAN_FRONTEND=noninteractive run apt-get install -y --only-upgrade openssh-server openssh-client
    AFTER="$(dpkg-query -W -f="\${Version}" openssh-server 2>/dev/null)"
    say "  openssh-server: ${BEFORE:-?}  ->  ${AFTER:-?}"
  else
    say "  no apk or apt-get: upgrade openssh with this platform s own tooling, then restart sshd."
    return 30
  fi
  # The package replaces the binary but leaves the old daemon running.
  validate_then_restart || return 31
  if [ "$DRY" != 1 ]; then
    NEWVER="$( { "$SSHD_BIN" -V 2>&1; "$SSHD_BIN" -\? 2>&1; } | grep -m1 -o "OpenSSH_[0-9][^ ,]*")"
    say "  sshd binary now reports: ${NEWVER:-unknown}"
    PID="$(pidof sshd 2>/dev/null | tr " " "\n" | head -1)"
    if [ -n "$PID" ]; then
      case "$(readlink "/proc/$PID/exe" 2>/dev/null)" in
        *"(deleted)"*) say "  WARNING: the running sshd still has a deleted binary mapped -- the restart did not take. Restart it by hand." ;;
        *) say "  running daemon is on the current binary (pid $PID)." ;;
      esac
    fi
  fi
  return 0
}

RC=0
case "$MODE" in
  mitigate) do_mitigate || RC=$? ;;
  upgrade)  do_upgrade  || RC=$? ;;
  both)     do_mitigate || RC=$?; [ $RC -eq 0 ] && { do_upgrade || RC=$?; } ;;
  revert-mitigation) do_revert_mitigation || RC=$? ;;
  auto)
    if command -v apk >/dev/null 2>&1; then
      say "auto: apk present -> upgrade path"
      do_upgrade || RC=$?
    else
      say "auto: no apk -> mitigation path"
      do_mitigate || RC=$?
    fi
    ;;
esac

say ""
if [ "$DRY" = 1 ]; then
  say "DRY RUN -- nothing above was actually changed."
else
  say "Done (rc=$RC). VERIFY NOW, from a NEW terminal, while this session is still open:"
  say "    ssh -o BatchMode=yes <host> true && echo LOGIN STILL WORKS"
fi
exit $RC
'

# shellcheck disable=SC2029
ssh -o BatchMode=yes -o ConnectTimeout="$TIMEOUT" -o StrictHostKeyChecking=accept-new -T \
  "$DEST" "$PRIV sh -s -- '$MODE' '$DRY' '$ALL_PACKAGES' '$ACCEPT_PW_LOSS' '$FORCE'" <<EOF
$REMOTE_SCRIPT
EOF
RC=$?

echo ""
if [ $DRY -eq 1 ]; then
  echo "sshole-fix: dry run finished (rc=$RC). Re-run with --yes to apply."
else
  echo "sshole-fix: finished (rc=$RC)."
  echo "sshole-fix: re-probe to confirm:"
  echo "  ssh $DEST '$PRIV sh -s -- --text' < $(dirname "$0")/sshole-probe.sh"
fi
exit $RC
