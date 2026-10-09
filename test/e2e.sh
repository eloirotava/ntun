#!/bin/sh
# Teste ponta a ponta no PC: servidor + cliente (ou o cliente MIPS no qemu)
# ligados por localhost; um servico de eco faz o papel do ssh do roteador.
#   test/e2e.sh <cliente> [qemu]
set -eu
CLIENT=$1
QEMU=${2:-}
T=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$T"' EXIT

set -- $(build/ntun-server keygen); SPRIV=$1 SPUB=$2
set -- $(build/ntun-server keygen); CPRIV=$1 CPUB=$2
set -- $(build/ntun-server keygen); XPRIV=$1 XPUB=$2   # chave nao autorizada
mkdir -p "$T/srv"
echo "$SPRIV" > "$T/srv/server.key"
echo "$CPUB 18300 teste" > "$T/srv/clients"
echo "$CPRIV" > "$T/c.key"
echo "$XPRIV" > "$T/x.key"

python3 -I -c '
import socket, threading
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", 18400)); s.listen(8)
def eco(c):
    while True:
        d = c.recv(65536)
        if not d: break
        c.sendall(d)
    c.close()
while True:
    c, _ = s.accept(); threading.Thread(target=eco, args=(c,), daemon=True).start()
' &
build/ntun-server "$T/srv" 18222 2>"$T/srv.log" &
sleep 1
$QEMU $CLIENT 18400 "$T/c.key" 127.0.0.1 18222 "$SPUB" 2>"$T/cli.log" &
sleep 4

# eco atraves do tunel: 3 sessoes simultaneas, 1 MB cada, conferidas
python3 -I - <<'PY'
import socket, os, hashlib, threading, sys
ok = []
def sessao(i):
    d = os.urandom(1 << 20)
    c = socket.create_connection(("127.0.0.1", 18300), timeout=60)
    got = bytearray()
    def rd():
        while len(got) < len(d):
            b = c.recv(65536)
            if not b: break
            got.extend(b)
    t = threading.Thread(target=rd); t.start()
    c.sendall(d); t.join(); c.close()
    ok.append(hashlib.sha256(d).digest() == hashlib.sha256(bytes(got)).digest())
for _ in range(2):  # 2 rodadas: a conexao em espera e refeita entre elas
    ts = [threading.Thread(target=sessao, args=(i,)) for i in range(3)]
    [t.start() for t in ts]; [t.join() for t in ts]
    import time; time.sleep(3)
print("sessoes ok:", sum(ok), "de", len(ok))
sys.exit(0 if all(ok) and len(ok) == 6 else 1)
PY

# chave nao autorizada: o servidor recusa e o cliente diz por que
$QEMU $CLIENT 18400 "$T/x.key" 127.0.0.1 18222 "$SPUB" 2>"$T/x.log" &
XP=$!
# chave do servidor errada: o cliente recusa
$QEMU $CLIENT 18400 "$T/c.key" 127.0.0.1 18222 "$XPUB" 2>"$T/w.log" &
WP=$!
sleep 4
kill $XP $WP 2>/dev/null || true
echo "--- servidor"; cat "$T/srv.log"
echo "--- cliente com chave nao autorizada"; cat "$T/x.log"
echo "--- cliente com chave do servidor errada"; cat "$T/w.log"
grep -q "chave nao autorizada" "$T/srv.log"
grep -q "nao autorizada" "$T/x.log"
grep -q "fechou no handshake\|nao e o esperado" "$T/w.log"
echo "e2e ok"
