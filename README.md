# sshole-audit

Find, prove and fix **\*sshole** — the OpenSSH password bypass where, on musl libc
without PAM, *any* password between 257 and 1024 bytes logs you in as an account
that is supposed to have no password at all.

Disclosed 2026-11-05 by Özgün Kültekin (Wakefield). Fixed in **OpenSSH 10.6p2**.
Alpine backported it to every supported branch. No CVE was assigned at the time
Alpine published.

```console
$ ssh root@alpine-box
root@alpine-box's password:        # 300 × "A"
alpine-box:~# id
uid=0(root) gid=0(root) groups=0(root),10(wheel)
```

---

## The bug in one paragraph

musl's `crypt()` returns the literal string `"*"` when it fails, and it fails for any
password longer than 256 bytes with a `$5$`/`$6$` setting (`KEY_MAX`). When an account's
`/etc/shadow` field is exactly `*`, sshd has no salt of its own, so it borrows one from
another account's real hash — `pick_salt()`, added in 2016 to close the CVE-2016-6210
timing oracle — hashes the supplied password with it, gets `"*"` back, and compares that
with the stored `"*"`. They match. glibc and libxcrypt return `NULL` or `"*0"`, never a
bare `"*"`, and a PAM stack never calls `crypt()` for a `*` field, so only
musl-without-PAM is affected.

Longer version, with the 1980→2026 history and the actual code path:
[`references/mechanism.md`](references/mechanism.md).

## Are you affected?

All four must hold. Miss one and you are not exploitable:

1. sshd linked against **musl** — Alpine, OpenWrt, Buildroot, Yocto, and many Docker images
2. **no PAM** — not linked against `libpam`, or `UsePAM no`. Alpine's `openssh-server` is
   built without PAM by default
3. **`PasswordAuthentication yes`** (the default) *and* the account actually reachable —
   not blocked by `PermitRootLogin`, `AllowUsers`, `DenyUsers`, `AllowGroups`,
   `DenyGroups` or a `Match` block
4. an account whose shadow field is **exactly `*`**, plus **another account with a
   `$5$`/`$6$` hash** to donate the salt

`!`, `!!`, `*LK*` and `!$6$…` are all safe — only a bare `*` matches. Note which side of
this an account with a real password sits on: it is the **salt donor**, not the victim.

**Not affected:** glibc/libxcrypt (Debian, Ubuntu, Fedora, RHEL…), any PAM stack with
`UsePAM yes`, Dropbear, OpenBSD, and any musl box with no `*` account or no salt donor.

## Quick start

No install, no dependencies on the target. The probe is a single POSIX `sh` script that
runs on busybox ash just as happily as bash, and it is piped in over stdin so nothing is
ever written to the remote host:

```sh
ssh root@host 'sh -s -- --text' < scripts/sshole-probe.sh
```

```
host:        alpine-box
os:          Alpine Linux v3.21 (alpine 3.21.3)  branch=3.21
sshd:        OpenSSH_9.9p2  [openssh-server 9.9_p2-r0]
libc:        musl (ldd: ld-musl)
pam:         linked=0 usepam= active=0
passwordauth:yes   permitrootlogin=yes
patch:       unpatched (need >= 9.9_p2-r1)
'*' accounts: root
  reachable: root
salt donors: sha=1 other=0
VERDICT:     vulnerable (critical, confidence high)
  - musl libc with a non-PAM sshd: the affected configuration.
  - Reachable "*" account(s) [root] plus a salt donor: a password of 257..1024 bytes
    authenticates as those accounts.
  - Confirmed locally: crypt() on this box returns "*" for a 300-byte password.
```

Run it as root. Without root it cannot read `/etc/shadow` or run `sshd -T`, and it says
so — `confidence` drops to `low`, `config_source` becomes `file-parse`, accounts report
`enumerable: false`, and `compromise.checked` is `false`.

### A whole fleet

```sh
scripts/sshole-hosts.sh --all --kamal ~/code/myapp > hosts.txt
scripts/sshole-scan.sh --hosts-file hosts.txt --out ./sshole-reports/run1
```

`sshole-hosts.sh` discovers hosts from `~/.ssh/config`, Kamal `config/deploy.yml` files,
`aws ec2 describe-instances`, `doctl`, and the Hatchbox API (`--hatchbox`, needs
`HATCHBOX_API_TOKEN`). The scanner probes up to `--jobs` hosts at once and writes
per-host JSON, a combined `all.jsonl` and a readable `report.txt`.

Exit status: `0` nothing vulnerable · `1` something is · `2` usage error · `3` a host
could not be probed.

### Fixing

```sh
scripts/sshole-fix.sh --host H --mode auto          # dry run: prints the plan
scripts/sshole-fix.sh --host H --mode auto --yes    # apply
```

| mode | what it does |
|---|---|
| `auto` | upgrade where a fixed package is reachable, otherwise mitigate |
| `upgrade` | `apk`/`apt` upgrade the openssh packages, then restart sshd |
| `mitigate` | `PasswordAuthentication no`, then restart sshd |
| `both` | mitigate first (instant), then upgrade |
| `revert-mitigation` | undo the mitigation |

It is **dry-run by default**, backs up every file it edits, requires `sshd -t` to pass
before any restart, rolls back and refuses to restart if it does not, and re-reads the
effective config afterwards. `--mode mitigate` **refuses** to disable password auth when
an account has a real password but no `authorized_keys` — that account would lose its
only way in — unless you pass `--accept-password-login-loss`.

**Verify from a new terminal before closing the session that applied the fix.**

### By hand, if you prefer

```sh
apk upgrade -U openssh openssh-server
rc-service sshd restart          # REQUIRED: the package does not restart the daemon
```

Upgrading alone leaves the old daemon running with the replaced binary still mapped —
`readlink /proc/$(pidof sshd)/exe` ending in `(deleted)` is the tell. The probe reports
that as verdict `needs_restart`, which is still exploitable.

## What the probe will and will not do

**It changes nothing.** It reads config, accounts and logs, parses `sshd -T`, and never
writes a file, restarts a service, installs anything, or attempts a login — not even
against the host it is running on. There is no exploit code in this repository.

**It never prints a password hash.** Shadow fields are reported only as a class —
`star`, `bang`, `bangbang`, `lk`, `locked_hash`, `hash:6`, `des`, `empty` — so reports
are safe to keep, diff and paste into a ticket.

It checks things that are easy to get wrong:

- **the right binary.** From OpenSSH 9.8 the authenticating code lives in `sshd-session`,
  and from 10.0 in `sshd-auth`. `crypt()` and PAM are linked *there*, so checking only
  `/usr/sbin/sshd` misreads PAM builds. The probe resolves all of them.
- **PAM actually in force**, not merely compiled in — `libpam` linked *and* `UsePAM yes`.
- **per-account reachability**, via `sshd -T -C user=…` so `Match` blocks are evaluated,
  plus `AllowUsers`/`DenyUsers`/`AllowGroups`/`DenyGroups` glob matching and
  `PermitRootLogin` for root specifically.
- **the running daemon vs the binary on disk**, via `/proc/<pid>/exe` and start time.
- **live confirmation of the libc behaviour**, safely: `busybox cryptpw -m sha512` on a
  300-byte password. If it answers `*`, this box's `crypt()` really does do it. No login
  is attempted to establish that.
- **whether it already happened.** The only trace sshd leaves is a successful *password*
  login for an account that cannot have one. It greps the auth logs for exactly that.

### Containers

An Alpine container is only exposed if it **actually runs sshd** — an Alpine Rails image
with no sshd has nothing to attack. The container pass checks `docker top` for a live
sshd first and only then execs in. Judge a container on three things: is sshd running,
*can* it start (host keys present), and is port 22 published. Patch one by **rebuilding
the image**, never with `apk upgrade` inside a running container — that dies with the
container.

## Fixed versions

Upstream: **OpenSSH 10.6p2**. Alpine's per-branch backports, from its 2026-11-05 advisory:

| branch | fixed | branch | fixed |
|---|---|---|---|
| edge | `10.6_p2-r0` | 3.20 | `9.7_p1-r6` |
| 3.24 | `10.3_p1-r2` | 3.19 | `9.6_p1-r3` |
| 3.23 | `10.2_p1-r1` | 3.18 | `9.3_p2-r4` |
| 3.22 | `10.0_p1-r11` | 3.17 | `9.1_p1-r7` |
| 3.21 | `9.9_p2-r1` | 3.16 | `9.0_p1-r6` |

Compared with `apk version -t`, the only correct comparator for apk versions. On
non-Alpine musl (OpenWrt, Buildroot, Yocto) a vendor backport does not show in the
version string, so the probe reports `unknown_backport` rather than guessing.

Alpine branches **before 3.19** ship an `sshd_config` with no `Include` line, so a
drop-in alone is silently ignored — `sshole-fix.sh` edits the main file too.

## Verdicts

| verdict | meaning |
|---|---|
| `vulnerable` | all four preconditions hold, unpatched |
| `needs_restart` | package fixed, but the running daemon still has the old binary mapped |
| `mitigated` | unpatched, but password auth or reachability closes the path |
| `at_risk_no_star` | musl + no PAM + unpatched, but no `*` account or no salt donor *today* |
| `patched` | at or above the fixed version for its branch |
| `not_affected` | glibc, PAM active, no sshd, or not Linux |
| `unknown` | could not determine — treat as unknown, not as safe |

## Use with Claude Code

The repository doubles as a [Claude Code](https://claude.com/claude-code) skill:

```sh
git clone https://github.com/schappim/sshole-audit ~/.claude/skills/sshole-audit
```

Then ask Claude to "check my servers for \*sshole", or run `/sshole-audit`. `SKILL.md`
tells the agent how to drive the scripts and — more usefully — how to read the results
without overclaiming. The scripts are plain POSIX `sh` and work fine on their own.

## Limitations

- A degraded (non-root) run cannot enumerate `*` accounts or read auth logs. It reports
  `enumerable: false` and `star_count: null` rather than `0`, precisely so a gap is not
  mistaken for a clean result. Don't report one as a clean bill of health.
- `sshd -T` is authoritative; a hand-parsed config is not. In `sshd_config` the **first**
  value for a keyword wins and `Include` position decides precedence, so an unreadable
  drop-in can invert the answer. The probe splices `Include`s in position and flags
  files it could not read, but as root you simply get the real answer.
- Cloud firewalls and AWS security groups are invisible from inside a host. The probe
  reports what sshd binds to and what the host firewall says, and nothing more.
- `Match` blocks keyed on criteria the probe cannot simulate (`Match Address` ranges,
  `Match Host` patterns) are evaluated against a placeholder client.

## Credits

The vulnerability was found and written up by **Özgün Kültekin** at **Wakefield**.
The fix is the OpenSSH project's. The backports and the advisory this tool's version
table comes from are Alpine's. This repository is an independent auditing tool and is
not affiliated with any of them.

- Alpine advisory: <https://alpinelinux.org/posts/2026-11-05-openssh-password-authentication-bypass/>
- musl `b3c4cc12` (2012), where `crypt()` started returning `"*"` on failure
- musl `88bf5a8a` (2012), which added `KEY_MAX 256`
- OpenSSH's 2016 `pick_salt()` change for CVE-2016-6210

## License

MIT — see [LICENSE](LICENSE).
