#!/bin/sh
# wsudp contra o servidor real: abre o tunel (TLS + upgrade WebSocket no
# wstunnel da VPS) e confere que chegou ao "tunel aberto".
#   test/wsudp_live.sh <wsudp> [qemu]
set -u
${2:-} $1 51999 2>/tmp/wsudp_live.log &
P=$!
sleep 12
kill $P 2>/dev/null
cat /tmp/wsudp_live.log
grep -q "tunel aberto" /tmp/wsudp_live.log && echo "wsudp ao vivo: ok"
