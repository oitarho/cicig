#!/bin/sh
set -eu

CHAIN="CICIG_CLIENTS"
POLICIES=$(mktemp)
trap 'rm -f "$POLICIES"' EXIT INT TERM
cat >"$POLICIES"

vpn_interface() {
  interfaces=""
  if command -v awg >/dev/null 2>&1; then
    interfaces=$(awg show interfaces 2>/dev/null || true)
  fi
  if [ -z "$interfaces" ] && command -v wg >/dev/null 2>&1; then
    interfaces=$(wg show interfaces 2>/dev/null || true)
  fi
  if [ -z "$interfaces" ]; then
    interfaces=$(ip -o link show | awk -F': ' '$2 ~ /^(wg|awg)/ {print $2; exit}')
  fi
  first_interface=$(printf '%s\n' "$interfaces" | awk '{print $1}')
  [ -n "$first_interface" ] || return 1
  printf '%s\n' "$first_interface"
}

valid_ipv4() {
  printf '%s\n' "$1" | awk -F. '
    NF != 4 { exit 1 }
    { for (i = 1; i <= 4; i++) if ($i !~ /^[0-9]+$/ || $i > 255) exit 1 }
  '
}

class_number() {
  printf '%s\n' "$1" | awk -F. '{ print (($3 * 256 + $4) % 65000) + 10 }'
}

while IFS='|' read -r state address p2p_blocked download_limit extra; do
  [ -n "$state$address$p2p_blocked$download_limit$extra" ] || continue
  [ "$state" = "active" ] || exit 2
  valid_ipv4 "$address" || exit 2
  [ "$p2p_blocked" = "0" ] || [ "$p2p_blocked" = "1" ] || exit 2
  case "$download_limit" in
    ''|*[!0-9]*) exit 2 ;;
  esac
  [ "$download_limit" -le 1000 ] || exit 2
  [ -z "$extra" ] || exit 2
done <"$POLICIES"

interface=$(vpn_interface)

iptables -N "$CHAIN" 2>/dev/null || true
iptables -C FORWARD -j "$CHAIN" 2>/dev/null || iptables -I FORWARD 1 -j "$CHAIN"
iptables -F "$CHAIN"

if tc qdisc show dev "$interface" | grep -q 'qdisc htb 1:'; then
  tc qdisc del dev "$interface" root
fi

needs_shaper=0
while IFS='|' read -r state address p2p_blocked download_limit extra; do
  [ -n "$state$address$p2p_blocked$download_limit$extra" ] || continue
  if [ "$download_limit" -gt 0 ]; then
    needs_shaper=1
    break
  fi
done <"$POLICIES"

if [ "$needs_shaper" -eq 1 ]; then
  tc qdisc add dev "$interface" root handle 1: htb default 1
  tc class add dev "$interface" parent 1: classid 1:1 htb rate 10000mbit ceil 10000mbit
fi

while IFS='|' read -r state address p2p_blocked download_limit extra; do
  [ -n "$state$address$p2p_blocked$download_limit$extra" ] || continue

  if [ "$p2p_blocked" -eq 1 ]; then
    for direction in source destination; do
      if [ "$direction" = "source" ]; then
        address_match="-s"
      else
        address_match="-d"
      fi
      # Common BitTorrent ports, including Transmission's default 51413.
      iptables -A "$CHAIN" "$address_match" "$address" -p tcp -m multiport --dports 6881:6999,51413 -j REJECT --reject-with tcp-reset
      iptables -A "$CHAIN" "$address_match" "$address" -p tcp -m multiport --sports 6881:6999,51413 -j REJECT --reject-with tcp-reset
      iptables -A "$CHAIN" "$address_match" "$address" -p udp -m multiport --dports 6881:6999,51413 -j DROP
      iptables -A "$CHAIN" "$address_match" "$address" -p udp -m multiport --sports 6881:6999,51413 -j DROP
      # Signature checks are best-effort and depend on the host xt_string module.
      iptables -A "$CHAIN" "$address_match" "$address" -p tcp -m string --algo bm --string "BitTorrent protocol" -j REJECT --reject-with tcp-reset 2>/dev/null || true
      iptables -A "$CHAIN" "$address_match" "$address" -p tcp -m string --algo bm --string "info_hash=" -j REJECT --reject-with tcp-reset 2>/dev/null || true
    done
  fi

  if [ "$download_limit" -gt 0 ]; then
    number=$(class_number "$address")
    class_hex=$(printf '%x' "$number")
    tc class add dev "$interface" parent 1:1 classid "1:$class_hex" htb \
      rate "${download_limit}mbit" ceil "${download_limit}mbit" burst 32k cburst 32k
    tc qdisc add dev "$interface" parent "1:$class_hex" handle "$class_hex:" fq_codel
    tc filter add dev "$interface" protocol ip parent 1: prio "$number" u32 \
      match ip dst "$address/32" flowid "1:$class_hex"
  fi
done <"$POLICIES"
