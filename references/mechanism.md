# *sshole: the mechanism, and why it survived ten years

Disclosed 2026-11-05 by Özgün Kültekin at Wakefield. Fixed in OpenSSH 10.6p2 the
same day. No CVE assigned at the time Alpine published its advisory.

## The chain

**1980** — 3BSD's `/etc/passwd` gives the `daemon` account a `*` in the hash field.
No password can hash to `*`, so the account can never be logged into. Unix still
does this.

**2012-08-09, musl `b3c4cc12`** — musl makes `crypt()` stop returning `NULL` on
failure, because callers wrote `strcmp(crypt(pw, salt), stored)` with no NULL check
and segfaulted. The replacement return value is an unmatchable string. They chose
`"*"` (or `"x"` when `setting[0] == '*'`).

**2012-08-29, musl `88bf5a8a`** — sha256/sha512 crypt lands with `#define KEY_MAX 256`
as DoS protection, since sha512crypt cost grows with password length. Past 256 bytes
it fails — and failure now means `"*"`.

**2016-07, OpenSSH (CVE-2016-6210)** — sshd answered instantly for nonexistent users
and a few ms slower for real ones, leaking which accounts exist. The fix hashes the
supplied password anyway, using a salt borrowed from another account's hash:
`pick_salt()`. The commit says "Determine appropriate salt for invalid users" — it
also catches real users whose field is `*`.

**2019, CVE-2019-5021** — Alpine's Docker images shipped with root having no password
at all. Alpine locks root with `!`.

**2022, Alpine `fbe926af` (3.16)** — but without PAM, `!` also blocks public-key login
(`allowed_user()` treats a `!` prefix as locked), and cloud images log in with keys. So
Alpine changes root from `!` to `*`. Still "locked" — and now matchable.

## The code

`sys_auth_passwd()` in `auth-passwd.c`:

```c
if (authctxt->valid && pw_password[0] && pw_password[1])
        salt = pw_password;          /* a real hash: use it as its own salt */
else
        salt = pick_salt();          /* "*" is 1 char, so we land here */

encrypted_password = xcrypt(password, salt);

return encrypted_password != NULL &&
    strcmp(encrypted_password, pw_password) == 0;
```

With `pw_password = "*"`: `pw_password[1]` is `'\0'`, so `salt = pick_salt()` returns
something like `"$6$Q0ycQif$"` taken from another account. `xcrypt(300_bytes, "$6$…")`
on musl exceeds `KEY_MAX` and returns `"*"`. `strcmp("*", "*") == 0`. Authenticated.

The upper bound is OpenSSH's own `MAX_PASSWORD_LEN` (1024), so the window is 257..1024
bytes. A `*` field is the only one that matches: `!` is one char but `strcmp("*","!")`
fails; `!!`, `*LK*` and `*0` are ≥ 2 chars so they become the salt themselves, and musl
returns `"x"` for a setting starting with `*`, which matches none of them.

If no account has a `$`-prefixed hash, `pick_salt()` falls back to the DES salt `"xx"`,
and musl's DES crypt has no length limit — so it returns a real hash, and nothing
matches. Hence the "needs a salt donor" precondition.

**An algorithm musl cannot compute at all** (`$7$`, `$y$`, `$gy$`) makes `crypt()` fail
for *any* password length, which would remove the 257-byte floor. The probe flags such
hashes as donors for that reason; this is conservative inference from the same code
path, not something the advisory states.

## Why nobody noticed

- OpenSSH's own tests run on OpenBSD and glibc; musl does not test sshd.
- Most distributions route sshd through PAM, which never calls `crypt()` for a `*`.
- A fresh box with no passwords set has no salt donor, so it is not affected.
- Near misses: Debian #714219 (2013) asked glibc to copy musl's `"*"`; libxcrypt ended
  up with `"*0"`, one character away. A musl thread in Dec 2024 discussed busybox
  `passwd` breaking on a 257-character password — same token, same limit, nobody said
  sshd. An OpenSSH commit on 2026-10-30 fixed `pick_salt()` for bcrypt hashes; the bug
  was four lines below.

## Not affected

glibc / libxcrypt, any PAM stack with `UsePAM yes`, Dropbear, OpenBSD, and any musl box
with no `*` account or no salt donor.
