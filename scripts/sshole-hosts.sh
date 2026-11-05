#!/bin/sh
# sshole-hosts.sh -- discover SSH hosts worth probing, from the sources that
# actually know: Hatchbox, Kamal config, ~/.ssh/config, AWS, DigitalOcean.
#
# Prints one host per line, "# source" commented, ready for
# `sshole-scan.sh --hosts-file`. Read-only: it queries APIs and reads config.
#
# Usage:
#   sshole-hosts.sh [--hatchbox] [--kamal DIR]... [--ssh-config] [--aws] [--do] [--all]
#
# --hatchbox needs HATCHBOX_API_TOKEN in the environment (or a `hatchbox`
# entry in the Claude MCP config) and npx on PATH. It is the best source for
# Hatchbox fleets because it reports the PUBLIC ip of every box, including the
# ones a topology diagram shows only by private address.

set -u
DO_HATCHBOX=0; DO_SSHCFG=0; DO_AWS=0; DO_DO=0; KAMAL_DIRS=""

while [ $# -gt 0 ]; do
  case "$1" in
    --hatchbox) DO_HATCHBOX=1 ;;
    --ssh-config) DO_SSHCFG=1 ;;
    --aws) DO_AWS=1 ;;
    --do) DO_DO=1 ;;
    --kamal) KAMAL_DIRS="$KAMAL_DIRS ${2:?--kamal needs a directory}"; shift ;;
    --all) DO_HATCHBOX=1; DO_SSHCFG=1; DO_AWS=1; DO_DO=1 ;;
    -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
    *) echo "sshole-hosts: unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ----------------------------------------------------------------- hatchbox
hbx_call() {
  # $1 tool, $2 json args. One npx session per call; slow but simple.
  { printf '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"sshole","version":"1"}}}\n'
    printf '{"jsonrpc":"2.0","method":"notifications/initialized"}\n'
    printf '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"%s","arguments":%s}}\n' "$1" "$2"
    sleep 15
  } | npx -y @hatchbox/hatchbox-mcp 2>/dev/null |
    sed -n 's/.*"text":"\(.*\)"}].*/\1/p' | head -1 |
    sed -e 's/\\n/\n/g' -e 's/\\"/"/g'
}

if [ $DO_HATCHBOX -eq 1 ]; then
  if [ -z "${HATCHBOX_API_TOKEN:-}" ]; then
    echo "# hatchbox: HATCHBOX_API_TOKEN not set, skipping" >&2
  elif ! command -v npx >/dev/null 2>&1; then
    echo "# hatchbox: npx not found, skipping" >&2
  elif ! command -v jq >/dev/null 2>&1; then
    echo "# hatchbox: jq required, skipping" >&2
  else
    echo "# --- hatchbox ---"
    acct="$(hbx_call hatchbox_list_accounts '{}' | jq -r '.[0].id' 2>/dev/null)"
    if [ -n "$acct" ] && [ "$acct" != null ]; then
      hbx_call hatchbox_list_account_clusters "{\"account_id\":$acct}" |
        jq -r '.[] | "\(.id)\t\(.name)"' 2>/dev/null |
      while IFS="$(printf '\t')" read -r cid cname; do
        [ -n "$cid" ] || continue
        hbx_call hatchbox_list_servers "{\"cluster_id\":$cid}" |
          jq -r --arg c "$cname" '.[] |
            "\(.public_ip // .private_ip)  # hatchbox \($c)/\(.name) roles=\((.roles//[])|join(",")) ubuntu=\(.ubuntu_version//"?") port=\(.ssh_port//22)"' 2>/dev/null
      done
    else
      echo "# hatchbox: no account returned (bad token?)" >&2
    fi
  fi
fi

# -------------------------------------------------------------------- kamal
for d in $KAMAL_DIRS; do
  for f in "$d"/config/deploy.yml "$d"/config/deploy.*.yml; do
    [ -r "$f" ] || continue
    echo "# --- kamal $f ---"
    # host entries under servers:/accessories:, plus builder remote
    awk '
      /^[[:space:]]*-[[:space:]]*[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+[[:space:]]*$/ { gsub(/[-[:space:]]/,""); print; next }
      /^[[:space:]]*host:[[:space:]]*/ { sub(/^[[:space:]]*host:[[:space:]]*/,""); print; next }
      /ssh:\/\// { match($0, /ssh:\/\/[^ ]+/); print substr($0, RSTART+6, RLENGTH-6); next }
    ' "$f" | sed 's/[",]//g' | sort -u | sed "s|\$| # kamal $(basename "$d")|"
  done
done

# --------------------------------------------------------------- ssh config
if [ $DO_SSHCFG -eq 1 ]; then
  echo "# --- ~/.ssh/config ---"
  awk 'tolower($1)=="host" {for(i=2;i<=NF;i++) if ($i !~ /[*?]/) print $i"  # ssh config"}' \
    "$HOME/.ssh/config" 2>/dev/null
fi

# --------------------------------------------------------------------- aws
if [ $DO_AWS -eq 1 ] && command -v aws >/dev/null 2>&1; then
  echo "# --- aws ec2 ---"
  aws ec2 describe-instances \
    --filters Name=instance-state-name,Values=running \
    --query 'Reservations[].Instances[].{ip:PublicIpAddress,priv:PrivateIpAddress,name:Tags[?Key==`Name`]|[0].Value}' \
    --output text 2>/dev/null | awk 'NF {print $2"  # aws "$1" ("$3")"}'
fi

# -------------------------------------------------------------- digitalocean
if [ $DO_DO -eq 1 ] && command -v doctl >/dev/null 2>&1; then
  echo "# --- digitalocean ---"
  doctl compute droplet list --format Name,PublicIPv4 --no-header 2>/dev/null |
    awk 'NF>1 {print $2"  # do "$1}'
fi
