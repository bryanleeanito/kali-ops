#!/bin/sh
# install.sh — pasang plugin kali-ops ke ~/.config/opencode/plugins/
set -e
SRC="$(cd "$(dirname "$0")" && pwd)"
DST="${OPENCODE_CONFIG_DIR:-$HOME/.config/opencode}"
TS="$(date +%Y%m%d-%H%M%S)"

mkdir -p "$DST/plugins"
for f in "$SRC"/plugins/*.js; do
  n="$(basename "$f")"
  [ -f "$DST/plugins/$n" ] && cp -f "$DST/plugins/$n" "$DST/plugins/$n.bak-$TS" && echo "[i] backup $n"
  cp -f "$f" "$DST/plugins/$n"
  echo "[OK] plugin $n -> $DST/plugins/$n"
done

cat <<'EOF'

NEXT:
  1. opencode reload        # muat plugin
  2. cek: tool namespace "kali" muncul (kali_sys_status, kali_tool_check, ...)
  3. tes guardrail: node tests/test_guardrail_kali.mjs
EOF
