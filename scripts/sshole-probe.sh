#!/bin/sh
# sshole-probe.sh -- read-only triage for the *sshole sshd password bypass.
#
# The bug (disclosed 2026-11-05, fixed in OpenSSH 10.6p2): musl's crypt()
# returns the literal string "*" when it fails, and it fails on any password
# longer than 256 bytes for $5$/$6$ settings (KEY_MAX). When an account's
# shadow field is exactly "*", sshd has no salt of its own, so it borrows a
# salt from another account's real hash (pick_salt(), added for CVE-2016-6210),
# hashes the attacker's password with it, gets "*" back, and compares it with
# the stored "*". They match. Any password of 257..1024 bytes logs that
# account in. PAM builds never call crypt() for a "*" field, and glibc /
# libxcrypt return NULL or "*0", so only musl-without-PAM is affected.
#
# This script CHANGES NOTHING. It reads config, accounts and logs, parses
# `sshd -T` output, and never writes a file, restarts a service, or attempts
# a login. It never prints a password hash: shadow fields are reported only
# as a class ("star", "bang", "hash:6"), so reports are safe to keep and paste.
#
# Usage:
#   sshole-probe.sh [--text] [--no-containers] [--no-logs] [--help]
#   ssh host 'sh -s -- --json' < sshole-probe.sh        # remote, root
#   ssh host 'sudo -n sh -s -- --json' < sshole-probe.sh
#
# Exit status: 0 probe ran (read the verdict), 2 bad usage.
# Verdict never affects exit status -- a non-zero exit means the probe broke.

PROBE_VERSION=1.2.0
FORMAT=json
DO_CONTAINERS=1
DO_LOGS=1
LOG_MATCH_LIMIT=40

while [ $# -gt 0 ]; do
  case "$1" in
    --json) FORMAT=json ;;
    --text) FORMAT=text ;;
    --no-containers) DO_CONTAINERS=0 ;;
    --containers) DO_CONTAINERS=1 ;;
    --no-logs) DO_LOGS=0 ;;
    --version) echo "sshole-probe $PROBE_VERSION"; exit 0 ;;
    -h|--help) sed -n '2,30p' "$0" 2>/dev/null || echo "see script header"; exit 0 ;;
    *) echo "sshole-probe: unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------------------------------------------------------------- utilities

NOTES=""
note() { NOTES="$NOTES
$1"; }

# JSON string escaping. Handles the characters that actually occur in our
# data (paths, usernames, version strings, log lines).
jesc() {
  printf '%s' "$1" | tr -d '\r' | tr '\t' ' ' | tr '\n' ' ' |
    sed -e 's/\\/\\\\/g' -e 's/"/\\"/g'
}
js() { printf '"%s"' "$(jesc "$1")"; }
# JSON list from newline-separated stdin
jlist() {
  _first=1; printf '['
  while IFS= read -r _l || [ -n "$_l" ]; do
    [ -n "$_l" ] || continue
    [ $_first -eq 1 ] || printf ','
    _first=0; js "$_l"
  done
  printf ']'
}
jbool() { [ "$1" = "1" ] && printf 'true' || printf 'false'; }
# emit raw value or null
jnum() { case "$1" in ''|*[!0-9]*) printf 'null' ;; *) printf '%s' "$1" ;; esac; }

have() { command -v "$1" >/dev/null 2>&1; }
# Count non-blank lines in a string. Always prints exactly one integer, which
# `grep -c . || echo 0` does not: on empty input grep prints 0 *and* exits 1,
# so the fallback fires too and you get "0\n0" in the middle of the JSON.
count_lines() { printf '%s' "$1" | awk 'NF{n++} END{print n+0}'; }

# ---------------------------------------------------------------- privilege

UID_NOW="$(id -u 2>/dev/null || echo 0)"
ESC=""
if [ "$UID_NOW" != "0" ]; then
  if have sudo && sudo -n true 2>/dev/null; then ESC="sudo -n"
  elif have doas && doas -n true 2>/dev/null; then ESC="doas -n"
  else note "Not root and no non-interactive sudo/doas: /etc/shadow and sshd -T are unavailable, so the account and config checks are incomplete. Re-run as root."
  fi
fi
priv() { if [ -n "$ESC" ]; then $ESC "$@"; else "$@"; fi; }

# ---------------------------------------------------------------- target os

HOSTNAME_NOW="$(hostname 2>/dev/null || cat /proc/sys/kernel/hostname 2>/dev/null || echo unknown)"
OS_ID=""; OS_VERSION=""; OS_PRETTY=""
if [ -r /etc/os-release ]; then
  OS_ID="$(. /etc/os-release 2>/dev/null; printf '%s' "$ID")"
  OS_VERSION="$(. /etc/os-release 2>/dev/null; printf '%s' "$VERSION_ID")"
  OS_PRETTY="$(. /etc/os-release 2>/dev/null; printf '%s' "$PRETTY_NAME")"
fi
[ -r /etc/alpine-release ] && ALPINE_RELEASE="$(cat /etc/alpine-release 2>/dev/null)" || ALPINE_RELEASE=""
KERNEL="$(uname -sr 2>/dev/null)"
ARCH="$(uname -m 2>/dev/null)"
OS_KIND="$(uname -s 2>/dev/null)"
if [ "$OS_KIND" != "Linux" ]; then
  if [ "$FORMAT" = text ]; then
    echo "host:    $HOSTNAME_NOW"
    echo "kernel:  $KERNEL"
    echo "VERDICT: not_affected -- $OS_KIND is not Linux, and this bug is specific to musl libc on Linux."
    exit 0
  fi
  printf '{\n  "schema": "sshole-probe/1",\n  "probe_version": %s,\n  "scanned_at": %s,\n' \
    "$(js "$PROBE_VERSION")" "$(js "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)")"
  printf '  "target": {"hostname": %s, "kernel": %s, "os_kind": %s},\n' \
    "$(js "$HOSTNAME_NOW")" "$(js "$KERNEL")" "$(js "$OS_KIND")"
  printf '  "verdict": {"state": "not_affected", "severity": "none", "confidence": "high", "reasons": [%s]},\n' \
    "$(js "$OS_KIND is not Linux; the *sshole bug is specific to musl libc on Linux. Nothing to check here.")"
  printf '  "notes": []\n}\n'
  exit 0
fi

IS_CONTAINER=0
if [ -f /.dockerenv ] || grep -qa 'docker\|containerd\|lxc\|kubepods' /proc/1/cgroup 2>/dev/null; then IS_CONTAINER=1; fi

# ---------------------------------------------------------------- find sshd

SSHD_BIN=""
for c in /usr/sbin/sshd /usr/bin/sshd /sbin/sshd /usr/local/sbin/sshd; do
  [ -x "$c" ] && { SSHD_BIN="$c"; break; }
done
[ -n "$SSHD_BIN" ] || SSHD_BIN="$(command -v sshd 2>/dev/null)"

DROPBEAR=""
for c in /usr/sbin/dropbear /usr/bin/dropbear /sbin/dropbear; do
  [ -x "$c" ] && { DROPBEAR="$c"; break; }
done

SSHD_PRESENT=0; [ -n "$SSHD_BIN" ] && SSHD_PRESENT=1

SSHD_VERSION=""
if [ $SSHD_PRESENT -eq 1 ]; then
  SSHD_VERSION="$( { "$SSHD_BIN" -V 2>&1; "$SSHD_BIN" -\? 2>&1; } | grep -m1 -o 'OpenSSH_[0-9][^ ,]*' 2>/dev/null)"
  [ -n "$SSHD_VERSION" ] || SSHD_VERSION="$(ssh -V 2>&1 | grep -m1 -o 'OpenSSH_[0-9][^ ,]*')"
fi

# `sshd -T` is the effective config, including drop-ins. Needs root.
SSHD_T=""
SSHD_T_OK=0
if [ $SSHD_PRESENT -eq 1 ]; then
  SSHD_T="$(priv "$SSHD_BIN" -T 2>/dev/null)"
  [ -n "$SSHD_T" ] && SSHD_T_OK=1
fi
getcfg() {
  [ $SSHD_T_OK -eq 1 ] || { printf ''; return; }
  printf '%s\n' "$SSHD_T" | awk -v k="$1" 'tolower($1)==k {$1=""; sub(/^ /,""); print; exit}'
}
# Fall back to a plain config parse when sshd -T is unavailable (non-root).
# Assemble the file the way sshd reads it: the main config in order, with each
# Include line replaced in place by the files it names. Order matters because
# in sshd_config the FIRST value for a keyword wins, so a drop-in included
# near the top overrides the main file further down.
UNREADABLE_INCLUDES=""
assemble_config() {
  _main=/etc/ssh/sshd_config
  [ -r "$_main" ] || return 0
  while IFS= read -r _line; do
    case "$(printf '%s' "$_line" | awk '{print tolower($1)}')" in
      include)
        _pat="$(printf '%s' "$_line" | sed 's/^[[:space:]]*[Ii][Nn][Cc][Ll][Uu][Dd][Ee][[:space:]]*//')"
        for _inc in $_pat; do
          for _f in $_inc; do
            [ -e "$_f" ] || continue
            if [ -r "$_f" ]; then cat "$_f"
            else UNREADABLE_INCLUDES="$UNREADABLE_INCLUDES$_f
"
            fi
          done
        done
        ;;
      *) printf '%s\n' "$_line" ;;
    esac
  done < "$_main"
}
getcfg_file() {
  assemble_config | awk -v k="$1" '$1 !~ /^#/ && tolower($1)==k {$1=""; sub(/^ /,""); print; exit}' 2>/dev/null
}
cfg() {
  v="$(getcfg "$1")"
  [ -n "$v" ] || v="$(getcfg_file "$1")"
  printf '%s' "$v"
}

# Provenance is decided once, out here -- not inside cfg(), whose assignments
# would be lost with the command substitution's subshell.
if [ $SSHD_T_OK -eq 1 ]; then CFG_SOURCE="sshd -T"; else CFG_SOURCE="file-parse"; fi
PW_AUTH="$(cfg passwordauthentication)"
KBD_AUTH="$(cfg kbdinteractiveauthentication)"
[ -n "$KBD_AUTH" ] || KBD_AUTH="$(cfg challengeresponseauthentication)"
PERMIT_ROOT="$(cfg permitrootlogin)"
USE_PAM="$(cfg usepam)"
PUBKEY_AUTH="$(cfg pubkeyauthentication)"
ALLOW_USERS="$(cfg allowusers)"
DENY_USERS="$(cfg denyusers)"
ALLOW_GROUPS="$(cfg allowgroups)"
DENY_GROUPS="$(cfg denygroups)"
SESSION_PATH="$(cfg sshdsessionpath)"
AUTH_PATH="$(cfg sshdauthpath)"
# OpenSSH defaults when a directive is absent entirely
[ -n "$PW_AUTH" ] || PW_AUTH="yes(default)"
[ -n "$PERMIT_ROOT" ] || PERMIT_ROOT="prohibit-password(default)"

UNREADABLE_INCLUDES="$(assemble_config >/dev/null 2>&1; printf '%s' "$UNREADABLE_INCLUDES")"
if [ "$CFG_SOURCE" = "file-parse" ]; then
  note "sshd -T was unavailable, so the config values above come from parsing sshd_config by hand. That parse cannot see computed defaults or Match blocks, and it is only as complete as the files this user can read. Treat every config value as indicative, not authoritative, and re-run as root."
fi
_ui="$(for f in /etc/ssh/sshd_config.d/*.conf; do [ -e "$f" ] && [ ! -r "$f" ] && printf '%s ' "$f"; done)"
if [ -n "$_ui" ]; then
  note "Unreadable sshd_config drop-in(s): $_ui -- these are included BEFORE the main file's own settings on a stock Ubuntu/Debian config, and the first value for a keyword wins, so they can override everything reported here. The config values above may be wrong."
fi

# ------------------------------------------------- libc + PAM of the binaries
# From 9.8 the authenticating code lives in sshd-session, from 10.0 in
# sshd-auth. crypt() and PAM are linked there, NOT necessarily into
# /usr/sbin/sshd -- checking only the listener misreads PAM builds.

AUTH_BINS=""
add_bin() { [ -n "$1" ] && [ -x "$1" ] && AUTH_BINS="$AUTH_BINS
$1"; }
add_bin "$SSHD_BIN"
add_bin "$SESSION_PATH"
add_bin "$AUTH_PATH"
sshd_dir="$(dirname "$SSHD_BIN" 2>/dev/null)"
for d in /usr/lib/openssh /usr/libexec/openssh /usr/libexec/ssh /usr/lib/ssh /usr/lib/misc "$sshd_dir"; do
  for b in sshd-session sshd-auth; do
    [ -x "$d/$b" ] && add_bin "$d/$b"
  done
done
AUTH_BINS="$(printf '%s\n' "$AUTH_BINS" | grep -v '^$' | sort -u)"

ldd_of() { ldd "$1" 2>/dev/null; }

LIBC=unknown
PAM_LINKED=0
LIBC_EVIDENCE=""
if [ -n "$AUTH_BINS" ] && have ldd; then
  _l="$(for b in $AUTH_BINS; do ldd_of "$b"; done 2>/dev/null)"
  case "$_l" in
    *ld-musl*|*libc.musl*) LIBC=musl; LIBC_EVIDENCE="ldd: ld-musl" ;;
  esac
  if [ "$LIBC" = unknown ]; then
    case "$_l" in
      *libc.so.6*|*ld-linux*|*libcrypt.so.1*) LIBC=glibc; LIBC_EVIDENCE="ldd: libc.so.6/ld-linux" ;;
    esac
  fi
  case "$_l" in *libpam.so*) PAM_LINKED=1 ;; esac
fi
if [ "$LIBC" = unknown ]; then
  # static binary, or no ldd (minimal image): fall back to the loader present
  for g in /lib/ld-musl-*.so.1; do [ -e "$g" ] && { LIBC=musl; LIBC_EVIDENCE="loader file $g"; break; }; done
fi
if [ "$LIBC" = unknown ]; then
  for g in /lib64/ld-linux-*.so.2 /lib/ld-linux-*.so.2 /lib/*/libc.so.6; do
    [ -e "$g" ] && { LIBC=glibc; LIBC_EVIDENCE="loader file $g"; break; }
  done
fi
if [ "$LIBC" = unknown ] && [ "$OS_ID" = alpine ]; then LIBC=musl; LIBC_EVIDENCE="os-release ID=alpine"; fi

# PAM is only in play when it is BOTH compiled in and switched on.
PAM_ACTIVE=0
case "$USE_PAM" in
  yes|Yes|YES) [ $PAM_LINKED -eq 1 ] && PAM_ACTIVE=1 ;;
esac
if [ $PAM_LINKED -eq 1 ] && [ -z "$USE_PAM" ]; then
  # PAM-capable build with no explicit UsePAM: upstream default is "no".
  note "sshd links libpam but UsePAM is not set; OpenSSH defaults UsePAM to no, so the crypt() path is still in use."
fi

# ---------------------------------------------------------------- packages

PKGS=""
PKG_MANAGER=""
if have apk; then
  PKG_MANAGER=apk
  PKGS="$(apk info -v 2>/dev/null | grep '^openssh' | sed 's/^\(.*\)-\([0-9][^-]*-r[0-9]*\)$/\1 \2/')"
elif have dpkg-query; then
  PKG_MANAGER=dpkg
  PKGS="$(dpkg-query -W -f='${Package} ${Version}\n' 'openssh*' 2>/dev/null | grep -v '^$')"
elif have rpm; then
  PKG_MANAGER=rpm
  PKGS="$(rpm -qa --qf '%{NAME} %{VERSION}-%{RELEASE}\n' 'openssh*' 2>/dev/null)"
fi
pkg_ver() { printf '%s\n' "$PKGS" | awk -v n="$1" '$1==n {print $2; exit}'; }

SERVER_PKG=""; SERVER_VER=""
for p in openssh-server-pam openssh-server openssh; do
  v="$(pkg_ver "$p")"
  [ -n "$v" ] && { SERVER_PKG="$p"; SERVER_VER="$v"; break; }
done

# ------------------------------------------------- Alpine fixed-version table
# From the Alpine advisory of 2026-11-05 (openssh password authentication
# bypass). A build at or above the listed version for its branch is fixed.
alpine_fixed_for() {
  case "$1" in
    3.16) echo "9.0_p1-r6" ;;
    3.17) echo "9.1_p1-r7" ;;
    3.18) echo "9.3_p2-r4" ;;
    3.19) echo "9.6_p1-r3" ;;
    3.20) echo "9.7_p1-r6" ;;
    3.21) echo "9.9_p2-r1" ;;
    3.22) echo "10.0_p1-r11" ;;
    3.23) echo "10.2_p1-r1" ;;
    3.24) echo "10.3_p1-r2" ;;
    edge) echo "10.6_p2-r0" ;;
    *) echo "" ;;
  esac
}

ALPINE_BRANCH=""
if [ "$OS_ID" = alpine ] || [ -n "$ALPINE_RELEASE" ]; then
  if grep -q '/edge/' /etc/apk/repositories 2>/dev/null; then
    ALPINE_BRANCH=edge
  else
    ALPINE_BRANCH="$(printf '%s' "$ALPINE_RELEASE" | awk -F. '{print $1"."$2}')"
    [ -n "$ALPINE_BRANCH" ] || ALPINE_BRANCH="$(sed -n 's|.*/v\([0-9][0-9]*\.[0-9][0-9]*\)/.*|\1|p' /etc/apk/repositories 2>/dev/null | head -1)"
  fi
fi

# Upstream version compare, for musl systems that are not Alpine.
# 10.6p2 is the fixed upstream release.
openssh_ge_fixed() {
  v="$(printf '%s' "$1" | sed 's/^OpenSSH_//')"
  maj="$(printf '%s' "$v" | awk -F'[.p]' '{print $1+0}')"
  min="$(printf '%s' "$v" | awk -F'[.p]' '{print $2+0}')"
  pl="$(printf '%s' "$v" | awk -F'p' '{print $2+0}')"
  [ -n "$maj" ] || return 1
  [ "$maj" -gt 10 ] && return 0
  [ "$maj" -lt 10 ] && return 1
  [ "$min" -gt 6 ] && return 0
  [ "$min" -lt 6 ] && return 1
  [ "$pl" -ge 2 ] && return 0
  return 1
}

PATCH_STATUS=unknown
PATCH_REQUIRED=""
PATCH_COMPARATOR=""
if [ "$LIBC" != musl ]; then
  PATCH_STATUS=not_applicable
  PATCH_COMPARATOR="n/a (glibc)"
elif [ -n "$ALPINE_BRANCH" ] && [ -n "$SERVER_VER" ]; then
  PATCH_REQUIRED="$(alpine_fixed_for "$ALPINE_BRANCH")"
  if [ -n "$PATCH_REQUIRED" ] && have apk; then
    PATCH_COMPARATOR="apk version -t"
    case "$(apk version -t "$SERVER_VER" "$PATCH_REQUIRED" 2>/dev/null)" in
      '='|'>') PATCH_STATUS=patched ;;
      '<') PATCH_STATUS=unpatched ;;
      *) PATCH_STATUS=unknown ;;
    esac
  else
    PATCH_COMPARATOR="no table for branch $ALPINE_BRANCH"
    if openssh_ge_fixed "$SSHD_VERSION"; then PATCH_STATUS=patched; else PATCH_STATUS=unknown_backport; fi
  fi
elif [ -n "$SSHD_VERSION" ]; then
  PATCH_COMPARATOR="upstream version string"
  if openssh_ge_fixed "$SSHD_VERSION"; then
    PATCH_STATUS=patched
  else
    # Non-Alpine musl (OpenWrt/Buildroot/Yocto) may carry a vendor backport
    # that the version string does not reveal.
    PATCH_STATUS=unknown_backport
    note "musl system that is not Alpine: $SSHD_VERSION is older than 10.6p2, but a vendor backport would not show in the version string. Treat as unpatched until the vendor's changelog says otherwise."
  fi
fi

# ---------------------------------------------- running daemon vs disk binary
# apk replaces the file; the daemon keeps running the old image until restart.
SSHD_PID=""
for p in $(pidof sshd 2>/dev/null); do SSHD_PID="$p"; break; done
if [ -z "$SSHD_PID" ] && [ -d /proc ]; then
  for d in /proc/[0-9]*; do
    [ -r "$d/comm" ] || continue
    case "$(cat "$d/comm" 2>/dev/null)" in
      sshd) SSHD_PID="${d#/proc/}"; break ;;
    esac
  done
fi
EXE_DELETED=0
STALE_DAEMON=0
if [ -n "$SSHD_PID" ]; then
  _exe="$(priv readlink "/proc/$SSHD_PID/exe" 2>/dev/null)"
  case "$_exe" in *"(deleted)"*) EXE_DELETED=1 ;; esac
  _bm="$(stat -c %Y "$SSHD_BIN" 2>/dev/null)"
  if [ -n "$_bm" ] && [ -r /proc/uptime ]; then
    _up="$(awk '{printf "%d", $1}' /proc/uptime 2>/dev/null)"
    _now="$(date +%s 2>/dev/null)"
    _st="$(awk '{print $22}' "/proc/$SSHD_PID/stat" 2>/dev/null)"
    if [ -n "$_up" ] && [ -n "$_now" ] && [ -n "$_st" ]; then
      _boot=$((_now - _up))
      _pstart=$((_boot + _st / 100))
      [ "$_pstart" -lt "$_bm" ] && STALE_DAEMON=1
    fi
  fi
  [ $EXE_DELETED -eq 1 ] && STALE_DAEMON=1
fi

LISTENERS="$( { netstat -tlnp 2>/dev/null || ss -tlnp 2>/dev/null; } | awk '/:22 |:22$/ {print $4}' | sort -u)"

# ---------------------------------------------------------------- accounts

SHADOW_SRC=""
SHADOW_DATA=""
if SHADOW_DATA="$(priv cat /etc/shadow 2>/dev/null)" && [ -n "$SHADOW_DATA" ]; then
  SHADOW_SRC=/etc/shadow
elif [ -r /etc/master.passwd ] && SHADOW_DATA="$(priv cat /etc/master.passwd 2>/dev/null)"; then
  SHADOW_SRC=/etc/master.passwd
else
  SHADOW_DATA="$(cat /etc/passwd 2>/dev/null)"
  SHADOW_SRC=/etc/passwd
  note "Could not read a shadow file; classified the password field from /etc/passwd instead. On a shadowed system that field is 'x' for everyone, so the account findings below are not conclusive."
fi

classify() {
  case "$1" in
    "") echo empty ;;
    '*') echo star ;;
    '!') echo bang ;;
    '!!') echo bangbang ;;
    '*LK*') echo lk ;;
    'x'|'X') echo x ;;
    '!'*) echo locked_hash ;;
    '$'*) echo "hash:$(printf '%s' "$1" | awk -F'$' '{print $2}')" ;;
    *) if [ "${#1}" = 13 ]; then echo des; else echo other; fi ;;
  esac
}

STAR_USERS=""
EMPTY_USERS=""
LOCKED_USERS=""
DONOR_SHA=""          # $5$/$6$ -- these fail over 256 bytes (KEY_MAX)
DONOR_OTHER=""        # algorithms musl cannot compute at all
HASH_ALGOS=""
OLDIFS="$IFS"
IFS='
'
for line in $SHADOW_DATA; do
  u="$(printf '%s' "$line" | cut -d: -f1)"
  f="$(printf '%s' "$line" | cut -d: -f2)"
  [ -n "$u" ] || continue
  k="$(classify "$f")"
  case "$k" in
    star) STAR_USERS="$STAR_USERS$u
" ;;
    empty) EMPTY_USERS="$EMPTY_USERS$u
" ;;
    bang|bangbang|lk|locked_hash) LOCKED_USERS="$LOCKED_USERS$u
" ;;
    hash:5|hash:6) DONOR_SHA="$DONOR_SHA$u
"; HASH_ALGOS="$HASH_ALGOS${k#hash:}
" ;;
    hash:*)
      a="${k#hash:}"
      HASH_ALGOS="$HASH_ALGOS$a
"
      case "$a" in
        2|2a|2b|2y|1) : ;;                      # musl computes these fine
        *) DONOR_OTHER="$DONOR_OTHER$u
" ;;      # $7$, $y$, $gy$ ... musl cannot
      esac ;;
    des) HASH_ALGOS="${HASH_ALGOS}des
" ;;
  esac
done
IFS="$OLDIFS"

DONOR_SHA_COUNT="$(count_lines "$DONOR_SHA")"
DONOR_OTHER_COUNT="$(count_lines "$DONOR_OTHER")"
STAR_COUNT="$(count_lines "$STAR_USERS")"

# Per-account detail: can sshd actually be reached as this user?
glob_match() { case "$2" in $1) return 0 ;; esac; return 1; }
in_list() {
  _u="$1"; _list="$2"
  for pat in $_list; do glob_match "$pat" "$_u" && return 0; done
  return 1
}
user_field() { awk -F: -v u="$1" '$1==u {print $'"$2"'; exit}' /etc/passwd 2>/dev/null; }

pwauth_for() {
  [ $SSHD_T_OK -eq 1 ] || { printf 'unknown'; return; }
  _o="$(priv "$SSHD_BIN" -T -C "user=$1,host=sshole-probe.invalid,addr=203.0.113.1" 2>/dev/null)"
  if [ -z "$_o" ]; then printf '%s' "$PW_AUTH"; return; fi
  _v="$(printf '%s\n' "$_o" | awk 'tolower($1)=="passwordauthentication"{print $2; exit}')"
  [ -n "$_v" ] && printf '%s' "$_v" || printf '%s' "$PW_AUTH"
}
permitroot_for() {
  [ $SSHD_T_OK -eq 1 ] || { printf '%s' "$PERMIT_ROOT"; return; }
  _o="$(priv "$SSHD_BIN" -T -C "user=root,host=sshole-probe.invalid,addr=203.0.113.1" 2>/dev/null)"
  _v="$(printf '%s\n' "$_o" | awk 'tolower($1)=="permitrootlogin"{print $2; exit}')"
  [ -n "$_v" ] && printf '%s' "$_v" || printf '%s' "$PERMIT_ROOT"
}

privilege_of() {
  _u="$1"; _out=""
  _groups="$(id -Gn "$_u" 2>/dev/null)"
  [ "$(user_field "$_u" 3)" = 0 ] && _out="uid0"
  for g in $_groups; do
    case "$g" in
      wheel|sudo|admin|root) _out="$_out sudo-group:$g" ;;
      docker) _out="$_out docker-group" ;;
    esac
  done
  if [ -r /etc/doas.conf ] || [ -d /etc/doas.d ]; then
    if { cat /etc/doas.conf 2>/dev/null; cat /etc/doas.d/* 2>/dev/null; } |
         grep -q "^[^#]*permit.*[ :]$_u\( \|$\)"; then _out="$_out doas"; fi
  fi
  if priv grep -rq "^[[:space:]]*$_u[[:space:]]" /etc/sudoers /etc/sudoers.d 2>/dev/null; then
    _out="$_out sudoers"
  fi
  printf '%s' "${_out# }"
}

EXPLOITABLE=""
STAR_JSON=""
first=1
IFS='
'
for u in $STAR_USERS; do
  [ -n "$u" ] || continue
  uid="$(user_field "$u" 3)"; shell="$(user_field "$u" 7)"; home="$(user_field "$u" 6)"
  pa="$(pwauth_for "$u")"
  reach=1; why=""
  case "$pa" in no|No|NO) reach=0; why="PasswordAuthentication no for this user" ;; esac
  if [ "$u" = root ]; then
    pr="$(permitroot_for)"
    case "$pr" in
      yes|Yes|YES) : ;;
      *) reach=0; why="${why:+$why; }PermitRootLogin $pr blocks password login for root" ;;
    esac
  else
    pr=""
  fi
  if [ -n "$ALLOW_USERS" ] && ! in_list "$u" "$ALLOW_USERS"; then
    reach=0; why="${why:+$why; }not in AllowUsers"
  fi
  if [ -n "$DENY_USERS" ] && in_list "$u" "$DENY_USERS"; then
    reach=0; why="${why:+$why; }listed in DenyUsers"
  fi
  if [ -n "$ALLOW_GROUPS" ]; then
    _ok=0
    for g in $(id -Gn "$u" 2>/dev/null); do in_list "$g" "$ALLOW_GROUPS" && _ok=1; done
    [ $_ok -eq 1 ] || { reach=0; why="${why:+$why; }no group in AllowGroups"; }
  fi
  if [ -n "$DENY_GROUPS" ]; then
    for g in $(id -Gn "$u" 2>/dev/null); do
      in_list "$g" "$DENY_GROUPS" && { reach=0; why="${why:+$why; }group in DenyGroups"; }
    done
  fi
  ak=0
  [ -n "$home" ] && priv test -s "$home/.ssh/authorized_keys" 2>/dev/null && ak=1
  nosh=0
  case "$shell" in */nologin|*/false) nosh=1 ;; esac
  privs="$(privilege_of "$u")"
  [ $reach -eq 1 ] && EXPLOITABLE="$EXPLOITABLE$u
"
  [ $first -eq 1 ] || STAR_JSON="$STAR_JSON,"
  first=0
  STAR_JSON="$STAR_JSON{\"user\":$(js "$u"),\"uid\":$(jnum "$uid"),\"shell\":$(js "$shell"),\"password_auth\":$(js "$pa"),\"permitrootlogin\":$(js "$pr"),\"reachable_by_password\":$(jbool $reach),\"blocked_because\":$(js "$why"),\"has_authorized_keys\":$(jbool $ak),\"shell_is_nologin\":$(jbool $nosh),\"privileges\":$(js "$privs")}"
done
IFS="$OLDIFS"
EXPLOITABLE_COUNT="$(count_lines "$EXPLOITABLE")"

# ------------------------------------------- local evidence of musl behaviour
# Safe, local, no login attempted: ask busybox's cryptpw (which calls the same
# crypt()) what a 300-byte password hashes to. On affected musl it answers "*".
CRYPT_TESTED=0; CRYPT_LONG_STAR=0; CRYPT_SHORT_OK=0; CRYPT_TOOL=""
if [ "$LIBC" = musl ] && have busybox && busybox cryptpw --help >/dev/null 2>&1; then
  CRYPT_TOOL="busybox cryptpw"
  _long="$(awk 'BEGIN{s="";for(i=0;i<300;i++)s=s "A";print s}')"
  _r_long="$(printf '%s\n' "$_long" | busybox cryptpw -m sha512 -S sshole00 2>/dev/null)"
  _r_short="$(printf 'shortpw\n' | busybox cryptpw -m sha512 -S sshole00 2>/dev/null)"
  CRYPT_TESTED=1
  [ "$_r_long" = '*' ] && CRYPT_LONG_STAR=1
  case "$_r_short" in '$6$'*) CRYPT_SHORT_OK=1 ;; esac
  unset _long _r_long _r_short
fi

# ---------------------------------------------------------------- verdict

VERDICT=unknown
SEVERITY=none
CONFIDENCE=high
REASONS=""
reason() { REASONS="$REASONS$1
"; }

if [ $SSHD_PRESENT -eq 0 ]; then
  VERDICT=not_affected
  reason "No OpenSSH sshd binary found on this system."
  [ -n "$DROPBEAR" ] && reason "Dropbear is installed; Dropbear does not have this bug."
elif [ "$LIBC" = glibc ]; then
  VERDICT=not_affected
  reason "sshd is linked against glibc/libxcrypt, which returns NULL or \"*0\" on crypt failure, never a bare \"*\"."
elif [ "$LIBC" = unknown ]; then
  VERDICT=unknown
  CONFIDENCE=low
  reason "Could not determine which libc sshd uses (no ldd, no recognisable loader)."
elif [ $PAM_ACTIVE -eq 1 ]; then
  VERDICT=not_affected
  reason "musl, but sshd links libpam and UsePAM is yes: the PAM stack handles a \"*\" field and sshd never calls crypt() for it."
else
  # musl, no PAM: the affected configuration. Now the specifics.
  reason "musl libc with a non-PAM sshd: the affected configuration."
  if [ "$PATCH_STATUS" = patched ] && [ $STALE_DAEMON -eq 0 ]; then
    VERDICT=patched
    reason "openssh $SERVER_VER is at or above the fixed version $PATCH_REQUIRED for this branch."
  elif [ "$PATCH_STATUS" = patched ] && [ $STALE_DAEMON -eq 1 ]; then
    VERDICT=needs_restart
    SEVERITY=critical
    reason "The package is fixed ($SERVER_VER) but the running daemon still has the old binary mapped. Upgrading does not restart sshd."
  else
    case "$PW_AUTH" in
      no|No|NO)
        VERDICT=mitigated
        reason "Unpatched, but PasswordAuthentication is no, which closes the only path to the bug."
        ;;
      *)
        if [ "$STAR_COUNT" = 0 ]; then
          if [ "$SHADOW_SRC" = /etc/passwd ]; then
            VERDICT=unknown
            CONFIDENCE=low
            reason "Unpatched with password auth on, but the shadow file could not be read, so \"*\" accounts could not be enumerated."
          else
            VERDICT=at_risk_no_star
            SEVERITY=medium
            reason "Unpatched with password auth on, but no account currently has \"*\" as its password field. One usermod, image rebuild or LDAP user away from exploitable."
          fi
        elif [ "$EXPLOITABLE_COUNT" = 0 ]; then
          VERDICT=mitigated
          reason "\"*\" accounts exist but sshd config blocks password login for every one of them (see blocked_because)."
        elif [ "$DONOR_SHA_COUNT" = 0 ] && [ "$DONOR_OTHER_COUNT" = 0 ]; then
          VERDICT=at_risk_no_star
          SEVERITY=medium
          reason "\"*\" accounts are reachable but no account has a \$5\$/\$6\$ hash to donate a salt, so crypt() is not pushed into its failure path today. Setting one password makes this exploitable."
        else
          VERDICT=vulnerable
          SEVERITY=critical
          reason "Reachable \"*\" account(s) [$(printf '%s' "$EXPLOITABLE" | tr '\n' ' ')] plus a salt donor: a password of 257..1024 bytes authenticates as those accounts."
          [ "$DONOR_OTHER_COUNT" != 0 ] && reason "A hash using an algorithm musl cannot compute is present, so the 257-byte floor may not even apply -- any password could match."
        fi
        ;;
    esac
  fi
  [ "$PATCH_STATUS" = unknown_backport ] && CONFIDENCE=medium
  if [ "$CFG_SOURCE" = "file-parse" ]; then
    CONFIDENCE=low
    case "$VERDICT" in
      mitigated|at_risk_no_star|patched)
        reason "This verdict rests on config values parsed from files rather than read from sshd -T, so it is provisional. Re-run as root to confirm."
        ;;
    esac
  fi
  if [ $CRYPT_TESTED -eq 1 ]; then
    if [ $CRYPT_LONG_STAR -eq 1 ]; then
      reason "Confirmed locally: crypt() on this box returns \"*\" for a 300-byte password (via $CRYPT_TOOL)."
    else
      reason "Local crypt() check did NOT return \"*\" for a 300-byte password; this libc may already be fixed."
      [ "$VERDICT" = vulnerable ] && { VERDICT=unknown; CONFIDENCE=low; }
    fi
  fi
fi
case "$VERDICT" in
  vulnerable|needs_restart) SEVERITY=critical ;;
  at_risk_no_star) SEVERITY=medium ;;
  mitigated) SEVERITY=low ;;
esac

# ---------------------------------------------------------------- compromise
# The only signal sshd leaves is a successful PASSWORD login for an account
# whose password field cannot match anything.
COMP_SOURCES=""
COMP_HITS=""
COMP_COUNT=0
LOG_SOURCES_READ=0
if [ $DO_LOGS -eq 1 ] && [ "$STAR_COUNT" != 0 ]; then
  _pat="$(printf '%s' "$STAR_USERS" | grep -v '^$' | awk '{printf "%s%s", sep, $0; sep="|"}')"
  if [ -n "$_pat" ]; then
    for f in /var/log/messages /var/log/auth.log /var/log/secure /var/log/messages.0 /var/log/auth.log.1; do
      [ -r "$f" ] || priv test -r "$f" 2>/dev/null || continue
      _h="$(priv grep -E "Accepted password for ($_pat) " "$f" 2>/dev/null | tail -n $LOG_MATCH_LIMIT)"
      COMP_SOURCES="$COMP_SOURCES$f
"
      [ -n "$_h" ] && COMP_HITS="$COMP_HITS$_h
"
    done
    if have zcat; then
      for f in /var/log/messages.*.gz /var/log/auth.log.*.gz; do
        [ -e "$f" ] || continue
        COMP_SOURCES="$COMP_SOURCES$f
"
        _h="$(priv zcat "$f" 2>/dev/null | grep -E "Accepted password for ($_pat) " | tail -n $LOG_MATCH_LIMIT)"
        [ -n "$_h" ] && COMP_HITS="$COMP_HITS$_h
"
      done
    fi
    if have journalctl; then
      COMP_SOURCES="$COMP_SOURCES journalctl
"
      _h="$(priv journalctl -u ssh -u sshd -u ssh.service --no-pager -o cat 2>/dev/null |
             grep -E "Accepted password for ($_pat) " | tail -n $LOG_MATCH_LIMIT)"
      [ -n "$_h" ] && COMP_HITS="$COMP_HITS$_h
"
    fi
    COMP_COUNT="$(count_lines "$COMP_HITS")"
    LOG_SOURCES_READ="$(count_lines "$COMP_SOURCES")"
  fi
fi
# "checked" means a log was actually read, not merely that we tried.
COMP_CHECKED=0
if [ "$LOG_SOURCES_READ" != 0 ]; then
  COMP_CHECKED=1
elif [ $DO_LOGS -eq 1 ] && [ "$STAR_COUNT" != 0 ]; then
  note "No auth log could be read, so the compromise check did not run. A count of 0 here means \"could not look\", not \"nothing found\". Re-run as root to search for accepted password logins."
fi
mtime_of() { [ -e "$1" ] && stat -c '%y' "$1" 2>/dev/null || printf ''; }

# ---------------------------------------------------------------- containers
CONTAINERS_JSON=""
CONTAINERS_SCANNED=0
if [ $DO_CONTAINERS -eq 1 ] && have docker && docker info >/dev/null 2>&1; then
  CONTAINERS_SCANNED=1
  _cfirst=1
  for c in $(docker ps -q 2>/dev/null); do
    _img="$(docker inspect --format '{{.Config.Image}}' "$c" 2>/dev/null)"
    _name="$(docker inspect --format '{{.Name}}' "$c" 2>/dev/null | sed 's|^/||')"
    _ports="$(docker inspect --format '{{json .NetworkSettings.Ports}}' "$c" 2>/dev/null)"
    _netmode="$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$c" 2>/dev/null)"
    _has_sshd=0
    docker top "$c" 2>/dev/null | grep -q '[s]shd' && _has_sshd=1
    _ssh_exposed=0
    case "$_ports" in *'"22/tcp":[{'*) _ssh_exposed=1 ;; esac
    _clibc=unknown; _cstars=""; _cpw=""; _cver=""
    if [ $_has_sshd -eq 1 ]; then
      # only pay for an exec when something is actually listening in there
      _cout="$(docker exec "$c" sh -c '
        l=unknown
        for g in /lib/ld-musl-*.so.1; do [ -e "$g" ] && l=musl; done
        [ "$l" = unknown ] && { for g in /lib64/ld-linux-*.so.2 /lib/*/libc.so.6; do [ -e "$g" ] && l=glibc; done; }
        echo "libc=$l"
        echo "stars=$(awk -F: "\$2==\"*\"{printf \"%s \", \$1}" /etc/shadow 2>/dev/null)"
        echo "ver=$( { /usr/sbin/sshd -V 2>&1; /usr/sbin/sshd -\? 2>&1; } | grep -m1 -o "OpenSSH_[0-9][^ ,]*")"
        echo "pw=$(/usr/sbin/sshd -T 2>/dev/null | awk "tolower(\$1)==\"passwordauthentication\"{print \$2}")"
      ' 2>/dev/null)"
      _clibc="$(printf '%s\n' "$_cout" | sed -n 's/^libc=//p')"
      _cstars="$(printf '%s\n' "$_cout" | sed -n 's/^stars=//p')"
      _cver="$(printf '%s\n' "$_cout" | sed -n 's/^ver=//p')"
      _cpw="$(printf '%s\n' "$_cout" | sed -n 's/^pw=//p')"
    fi
    _cverdict=not_affected
    if [ $_has_sshd -eq 1 ]; then
      if [ "$_clibc" = musl ]; then
        if [ -n "$_cstars" ] && [ "$_cpw" != no ]; then _cverdict=vulnerable_review
        else _cverdict=review; fi
      fi
    fi
    [ $_cfirst -eq 1 ] || CONTAINERS_JSON="$CONTAINERS_JSON,"
    _cfirst=0
    CONTAINERS_JSON="$CONTAINERS_JSON{\"name\":$(js "$_name"),\"image\":$(js "$_img"),\"network_mode\":$(js "$_netmode"),\"runs_sshd\":$(jbool $_has_sshd),\"port_22_published\":$(jbool $_ssh_exposed),\"libc\":$(js "${_clibc:-unknown}"),\"sshd_version\":$(js "$_cver"),\"password_auth\":$(js "$_cpw"),\"star_accounts\":$(js "$_cstars"),\"verdict\":$(js "$_cverdict")}"
  done
fi

# ---------------------------------------------------------------- output

if [ "$FORMAT" = text ]; then
  echo "host:        $HOSTNAME_NOW"
  echo "os:          ${OS_PRETTY:-unknown} (${OS_ID:-?} ${OS_VERSION:-?})${ALPINE_BRANCH:+  branch=$ALPINE_BRANCH}"
  echo "sshd:        ${SSHD_VERSION:-not found}  ${SERVER_PKG:+[$SERVER_PKG $SERVER_VER]}"
  echo "libc:        $LIBC ${LIBC_EVIDENCE:+($LIBC_EVIDENCE)}"
  echo "pam:         linked=$PAM_LINKED usepam=${USE_PAM:-unset} active=$PAM_ACTIVE"
  echo "passwordauth:${PW_AUTH}   permitrootlogin=${PERMIT_ROOT}"
  echo "patch:       $PATCH_STATUS ${PATCH_REQUIRED:+(need >= $PATCH_REQUIRED)}"
  echo "stale sshd:  $STALE_DAEMON (exe deleted=$EXE_DELETED)"
  echo "'*' accounts: $(printf '%s' "$STAR_USERS" | tr '\n' ' ')"
  echo "  reachable: $(printf '%s' "$EXPLOITABLE" | tr '\n' ' ')"
  echo "salt donors: sha=$DONOR_SHA_COUNT other=$DONOR_OTHER_COUNT"
  echo "VERDICT:     $VERDICT ($SEVERITY, confidence $CONFIDENCE)"
  printf '%s' "$REASONS" | sed 's/^/  - /'
  echo "suspicious password accepts: $COMP_COUNT"
  [ -n "$COMP_HITS" ] && printf '%s' "$COMP_HITS" | sed 's/^/  ! /'
  [ -n "$NOTES" ] && { echo "notes:"; printf '%s' "$NOTES" | sed 's/^/  * /'; }
  exit 0
fi

printf '{\n'
printf '  "schema": "sshole-probe/1",\n'
printf '  "probe_version": %s,\n' "$(js "$PROBE_VERSION")"
printf '  "scanned_at": %s,\n' "$(js "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null)")"
printf '  "target": {"hostname": %s, "os_id": %s, "os_version": %s, "pretty": %s, "alpine_release": %s, "alpine_branch": %s, "kernel": %s, "arch": %s, "in_container": %s},\n' \
  "$(js "$HOSTNAME_NOW")" "$(js "$OS_ID")" "$(js "$OS_VERSION")" "$(js "$OS_PRETTY")" "$(js "$ALPINE_RELEASE")" "$(js "$ALPINE_BRANCH")" "$(js "$KERNEL")" "$(js "$ARCH")" "$(jbool $IS_CONTAINER)"
printf '  "privilege": {"uid": %s, "escalation": %s, "shadow_source": %s, "sshd_T": %s, "config_source": %s},\n' \
  "$(jnum "$UID_NOW")" "$(js "${ESC:-none}")" "$(js "$SHADOW_SRC")" "$(jbool $SSHD_T_OK)" "$(js "$CFG_SOURCE")"
printf '  "sshd": {"present": %s, "path": %s, "version": %s, "libc": %s, "libc_evidence": %s, "pam_linked": %s, "pam_active": %s, "auth_binaries": ' \
  "$(jbool $SSHD_PRESENT)" "$(js "$SSHD_BIN")" "$(js "$SSHD_VERSION")" "$(js "$LIBC")" "$(js "$LIBC_EVIDENCE")" "$(jbool $PAM_LINKED)" "$(jbool $PAM_ACTIVE)"
printf '%s' "$AUTH_BINS" | jlist
printf ', "package": {"manager": %s, "name": %s, "version": %s}, "all_packages": ' \
  "$(js "$PKG_MANAGER")" "$(js "$SERVER_PKG")" "$(js "$SERVER_VER")"
printf '%s' "$PKGS" | jlist
printf ', "dropbear": %s, "pid": %s, "exe_deleted": %s, "stale_daemon": %s, "listeners": ' \
  "$(js "$DROPBEAR")" "$(jnum "$SSHD_PID")" "$(jbool $EXE_DELETED)" "$(jbool $STALE_DAEMON)"
printf '%s' "$LISTENERS" | jlist
printf '},\n'
printf '  "config": {"passwordauthentication": %s, "kbdinteractiveauthentication": %s, "permitrootlogin": %s, "usepam": %s, "pubkeyauthentication": %s, "allowusers": %s, "denyusers": %s, "allowgroups": %s, "denygroups": %s},\n' \
  "$(js "$PW_AUTH")" "$(js "$KBD_AUTH")" "$(js "$PERMIT_ROOT")" "$(js "$USE_PAM")" "$(js "$PUBKEY_AUTH")" \
  "$(js "$ALLOW_USERS")" "$(js "$DENY_USERS")" "$(js "$ALLOW_GROUPS")" "$(js "$DENY_GROUPS")"
if [ "$SHADOW_SRC" = /etc/passwd ] && [ -e /etc/shadow ]; then
  ACCOUNTS_ENUMERABLE=0
  STAR_COUNT_JSON=null
else
  ACCOUNTS_ENUMERABLE=1
  STAR_COUNT_JSON="$(jnum "$STAR_COUNT")"
fi
printf '  "accounts": {"enumerable": %s, "star_count": %s, "star": [%s], "exploitable": ' \
  "$(jbool $ACCOUNTS_ENUMERABLE)" "$STAR_COUNT_JSON" "$STAR_JSON"
printf '%s' "$EXPLOITABLE" | jlist
printf ', "empty_password": '
printf '%s' "$EMPTY_USERS" | jlist
if [ "$ACCOUNTS_ENUMERABLE" = 0 ]; then _dsha=null; _doth=null; else _dsha="$(jnum "$DONOR_SHA_COUNT")"; _doth="$(jnum "$DONOR_OTHER_COUNT")"; fi
printf ', "locked_safe_count": %s, "salt_donors_sha": %s, "salt_donors_musl_unsupported": %s, "hash_algorithms": ' \
  "$(count_lines "$LOCKED_USERS")" "$_dsha" "$_doth"
printf '%s' "$HASH_ALGOS" | sort -u | jlist
printf '},\n'
printf '  "crypt_evidence": {"tested": %s, "tool": %s, "long_password_returns_star": %s, "short_password_hashes_ok": %s},\n' \
  "$(jbool $CRYPT_TESTED)" "$(js "$CRYPT_TOOL")" "$(jbool $CRYPT_LONG_STAR)" "$(jbool $CRYPT_SHORT_OK)"
printf '  "patch": {"status": %s, "installed": %s, "required": %s, "comparator": %s},\n' \
  "$(js "$PATCH_STATUS")" "$(js "$SERVER_VER")" "$(js "$PATCH_REQUIRED")" "$(js "$PATCH_COMPARATOR")"
printf '  "verdict": {"state": %s, "severity": %s, "confidence": %s, "reasons": ' \
  "$(js "$VERDICT")" "$(js "$SEVERITY")" "$(js "$CONFIDENCE")"
printf '%s' "$REASONS" | jlist
printf '},\n'
printf '  "compromise": {"checked": %s, "suspicious_accept_count": %s, "suspicious_accepts": ' \
  "$(jbool $COMP_CHECKED)" "$(jnum "$COMP_COUNT")"
printf '%s' "$COMP_HITS" | jlist
printf ', "log_sources_readable": %s, "sources": ' "$(jnum "$LOG_SOURCES_READ")"
printf '%s' "$COMP_SOURCES" | jlist
printf ', "mtimes": {"etc_passwd": %s, "etc_shadow": %s, "root_authorized_keys": %s}},\n' \
  "$(js "$(mtime_of /etc/passwd)")" "$(js "$(mtime_of /etc/shadow)")" "$(js "$(mtime_of /root/.ssh/authorized_keys)")"
printf '  "containers": {"scanned": %s, "list": [%s]},\n' "$(jbool $CONTAINERS_SCANNED)" "$CONTAINERS_JSON"
printf '  "notes": '
printf '%s' "$NOTES" | jlist
printf '\n}\n'
