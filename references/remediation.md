# Remediation playbooks

## Alpine host (the real fix)

```sh
apk upgrade -U openssh openssh-server    # or: apk upgrade -U -a
rc-service sshd restart                  # REQUIRED -- the package does not restart it
sshd -T | grep -i passwordauthentication
apk info -v | grep openssh               # compare with the branch table in SKILL.md
```

Upgrading alone leaves the old daemon running with the replaced binary still mapped;
`readlink /proc/$(pidof sshd)/exe` showing `(deleted)` is the tell. The probe reports
this as `stale_daemon` / verdict `needs_restart`.

If `apk upgrade` does not change the version, the box is pinned to a branch whose
repositories no longer carry the fix. Check `/etc/apk/repositories`, then mitigate.

## Can't upgrade yet — mitigate

```sh
mkdir -p /etc/ssh/sshd_config.d
echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/00-no-passwords.conf
# Alpine < 3.19 has no Include line, so edit the main file too:
sed -i.bak -e 's/^\(\s*PasswordAuthentication[^y#]*\)yes/\1no/i' /etc/ssh/sshd_config
sshd -t && rc-service sshd restart
sshd -T | grep -i passwordauthentication     # must print: passwordauthentication no
```

**Before you do this**, make sure every account that currently logs in with a password
has a working key — otherwise you lock yourself out. `sshole-fix.sh --mode mitigate`
refuses to proceed when it finds an account with a real hash and no `authorized_keys`.

## Containers (Kamal, Compose, anything)

An Alpine container is only exposed if it **runs sshd**. Check, in order:

```sh
docker top <container> | grep -w sshd            # is it actually running?
docker exec <c> sh -c '/usr/sbin/sshd -T' 2>&1   # could it even start? (host keys)
docker inspect <c> --format '{{json .NetworkSettings.Ports}}'   # is 22 published?
```

A container with sshd installed but not running, no host keys, and no published port
is not exploitable — note it and move on. Fix a real one by **rebuilding the image**
with an updated base (`FROM alpine:3.22` → rebuild pulls the patched `openssh`), not by
`apk upgrade` inside the running container, which is lost on the next deploy.

Watch for build-infrastructure images too: `moby/buildkit` is Alpine-based and ships
`openssh-server`, though it does not run it.

## Hatchbox

Hatchbox provisions **Ubuntu**, so hosts are glibc + PAM and not affected by this bug.
Two things still matter:

- **Every box can be internet-facing.** The topology diagram shows VPC addresses, but
  `hatchbox_list_servers` returns a `public_ip` for each one, and sshd typically binds
  `0.0.0.0:22` on all of them. Verify with an outside `nc -z -w5 <public_ip> 22`.
- **`deploy` usually lacks passwordless sudo**, so probes run degraded. To complete the
  `/etc/shadow` and auth-log halves you need a root-capable run.

Discover the fleet with `sshole-hosts.sh --hatchbox` (needs `HATCHBOX_API_TOKEN`).

## Kamal

Kamal hosts are whatever you provisioned (usually Ubuntu → not affected). The risk is
the **images**, so scan running containers on each host. Patch by rebuilding and
redeploying, not in place.

## If a box was compromised

The only trace is `Accepted password for <user>` where `<user>` has a `*` field. Logs:
`/var/log/messages` (Alpine/busybox syslogd), `/var/log/auth.log`, `/var/log/secure`,
or journalctl. sshd does not record password length, so there is no other signal.

If you find one, or cannot rule it out:
1. Treat the host as compromised; do not just patch it.
2. Rotate every credential the host could reach, and all host keys.
3. Review `authorized_keys` for every account, new users, `doas`/`sudo` config and use,
   cron and systemd timers, and the mtimes on `/etc/passwd` and `/etc/shadow`.
4. Prefer rebuilding the host over cleaning it.

## Hardening worth doing anyway

- `PasswordAuthentication no` everywhere you can.
- `PermitRootLogin prohibit-password` rather than `yes`, so the intent does not rest on
  the password setting staying off.
- On Alpine, `openssh-server-pam` with `UsePAM yes` takes the whole `crypt()` path out of
  play. Test it in staging first: the PAM build changes how locked accounts behave.
