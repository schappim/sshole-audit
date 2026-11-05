---
name: sshole-audit
description: Find, prove, fix and verify the "*sshole" OpenSSH password-bypass (musl crypt() returns "*", so any 257..1024 byte password authenticates as a "*" shadow account) across a fleet of servers and Docker containers. Use when asked to check, audit, triage, patch or harden servers against *sshole / the Alpine sshd long-password bypass / the musl crypt bug fixed in OpenSSH 10.6p2; when asked whether Alpine images or containers are affected; when asked to check whether a box was already broken into this way; and for fleet-wide "am I vulnerable" sweeps over Hatchbox, Kamal, AWS or DigitalOcean hosts.
---

# *sshole audit

Disclosed 2026-11-05, fixed in OpenSSH 10.6p2. No CVE at the time Alpine published.

## The bug in one paragraph

musl's `crypt()` returns the literal string `"*"` when it fails, and it fails for
any password longer than 256 bytes with a `$5$`/`$6$` setting (`KEY_MAX`). When an
account's shadow field is exactly `*`, sshd has no salt of its own, so it borrows a
salt from some other account's real hash (`pick_salt()`, added in 2016 to fix the
CVE-2016-6210 timing oracle), hashes the supplied password with it, gets `"*"` back,
and compares that with the stored `"*"`. They match. Any password of 257..1024 bytes
logs in as that account. glibc/libxcrypt return `NULL` or `"*0"`, never a bare `"*"`,
and a PAM stack never calls `crypt()` for a `*` field — so only musl-without-PAM is hit.

## The four preconditions — all must hold

1. sshd linked against **musl** (Alpine, OpenWrt, Buildroot, Yocto)
2. **no PAM**: not linked to `libpam`, or `UsePAM no`
3. **PasswordAuthentication yes** *and the account actually reachable* (not blocked by
   `PermitRootLogin`, `AllowUsers`, `DenyUsers`, `AllowGroups`, `DenyGroups`, or a `Match` block)
4. an account whose shadow field is **exactly `*`**, plus **another account with a `$5$`/`$6$` hash**
   to donate the salt

Miss any one and the box is not exploitable. `!`, `!!`, `*LK*` and `!$6$…` are all safe —
only a bare `*` matches. Note which side of this an account with a real password is on:
it is the **salt donor**, not the victim.

## Workflow

### 1. Discover hosts
```sh
scripts/sshole-hosts.sh --all --kamal ~/code/myapp > hosts.txt
```
`--hatchbox` needs `HATCHBOX_API_TOKEN` and is the best source for a Hatchbox fleet:
it returns the **public** IP of every box. **Do not trust a topology diagram's private
addresses as an isolation boundary** — Hatchbox shows the VPC address, and in practice
every box in a "private" cluster can still have a public IP with sshd on `0.0.0.0:22`.
Confirm exposure per box from cloud metadata plus an outside `nc -z -w5 <ip> 22`.

### 2. Probe (read-only, changes nothing)
```sh
scripts/sshole-scan.sh --hosts-file hosts.txt --out ./sshole-reports/run1
ssh host 'sudo -n sh -s -- --text' < scripts/sshole-probe.sh    # single host
```
The probe never writes a file, restarts a service or attempts a login, and **never
prints a password hash** — shadow fields are reported only as a class (`star`,
`bang`, `hash:6`), so its output is safe to keep and paste.

**Run it as root.** Without root it cannot read `/etc/shadow` or run `sshd -T`, and
it says so: `verdict.confidence` drops to `low`, `config_source` becomes `file-parse`,
and `compromise.checked` is `false`. A degraded run's `star_count: 0` means *"could not
look"*, not *"no star accounts"* — never report it as the latter.

### 3. Interpret
| verdict | meaning |
|---|---|
| `vulnerable` | all four preconditions hold, unpatched. Fix now. |
| `needs_restart` | package is fixed but the running daemon still has the old binary mapped. Still exploitable. |
| `mitigated` | unpatched, but password auth (or per-account reachability) closes the path |
| `at_risk_no_star` | musl + no PAM + unpatched, but no `*` account or no salt donor *today*. One `usermod`, image rebuild or new password away. Patch it. |
| `patched` | at or above the fixed version for its branch |
| `not_affected` | glibc, PAM active, no sshd, or not Linux |
| `unknown` | could not determine — say so, don't round it to safe |

### 4. Fix
```sh
scripts/sshole-fix.sh --host H --mode auto            # dry run, prints the plan
scripts/sshole-fix.sh --host H --mode auto --yes      # apply
```
Dry run by default. Backs up every file it edits, requires `sshd -t` to pass before any
restart, rolls back if it does not, and re-reads the effective config afterwards.
`--mode mitigate` **refuses** to disable password auth when an account has a real
password but no `authorized_keys` (that account would lose its only way in); override
with `--accept-password-login-loss` only when you are certain.

**Always verify from a NEW terminal before closing the session that applied the fix.**

### 5. Check whether it already happened
The only trace sshd leaves is a successful **password** login for an account that
cannot have a password. The probe greps the auth logs for exactly that and reports
`compromise.suspicious_accepts`. A non-zero count means treat the box as compromised:
rotate credentials and keys, review `doas`/`sudo` use, new users, new authorized_keys,
and the mtimes on `/etc/passwd` and `/etc/shadow` (the probe reports those too).

## Containers

An Alpine container is only exposed if it **actually runs sshd**. An Alpine Rails image
with no sshd has nothing to attack. The probe's container pass checks `docker top` for a
live sshd first and only then execs in to check libc, `*` accounts and password auth.
Judge a container on three things: is sshd running, can it start (host keys present), and
is port 22 published. Patch a container by **rebuilding the image**, never by `apk upgrade`
inside a running container — the change dies with the container.

## Fixed versions

Upstream: **OpenSSH 10.6p2**. Alpine backported per branch (from Alpine's 2026-11-05 advisory):

| branch | fixed | branch | fixed |
|---|---|---|---|
| edge | 10.6_p2-r0 | 3.20 | 9.7_p1-r6 |
| 3.24 | 10.3_p1-r2 | 3.19 | 9.6_p1-r3 |
| 3.23 | 10.2_p1-r1 | 3.18 | 9.3_p2-r4 |
| 3.22 | 10.0_p1-r11 | 3.17 | 9.1_p1-r7 |
| 3.21 | 9.9_p2-r1 | 3.16 | 9.0_p1-r6 |

The probe compares with `apk version -t`, which is the only correct comparator for apk
versions. On non-Alpine musl (OpenWrt/Buildroot/Yocto) a vendor backport will not show in
the version string, so it reports `unknown_backport` rather than guessing.

Alpine branches **before 3.19** ship an `sshd_config` with no `Include` line, so a drop-in
alone is silently ignored — the fix script edits the main file too.

## Rules

- Never report a degraded (non-root) run as a clean bill of health.
- Never conclude "not exposed" from a topology diagram. Prove it with metadata + an
  outside connect, and say plainly that cloud firewalls and security groups are invisible
  from inside the box.
- `sshd -T` is authoritative; a hand-parsed config is not. In `sshd_config` the **first**
  value for a keyword wins and `Include` position decides precedence, so an unreadable
  drop-in can invert the answer.
- Quote the actual evidence (version strings, config values, `ldd` output) in findings.

See `references/mechanism.md` for the full history and `references/remediation.md` for
the Hatchbox / Kamal / Docker playbooks.
