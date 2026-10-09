/* wsudp (C): cliente wstunnel (v10) so de UDP, para o WireGuard sair por WSS
 * na 443. Porte do wsudp em Zig: wss://br.rotava.com/wstunnel/events, cujo
 * wstunnel so aceita o destino 127.0.0.1:51820 (o WireGuard da VPS). O wg
 * local aponta o endpoint do peer para 127.0.0.1:<porta> e cada datagrama vai
 * num quadro WebSocket binario, por dentro de TLS 1.3.
 *
 * Uso: wsudp [porta-local]   (padrao 51820)
 *
 * TLS 1.3 so com o certificado Ed25519 fixado (cert.h), sem datas: nao
 * espera o NTP. Uma thread, poll() no UDP do wg e no socket da VPS. */
#include "util.h"
#include "tls13.h"
#include "ws.h"
#include "cert.h"

#define SERVER_HOST  "br.rotava.com"
#define TLS_NAME     "wsudp.rotava.internal"
#define PATH         "/wstunnel/events"
#define DEAD_S       90 /* sem nada do servidor (nem o pong): conexao morta */
#define PING_S       25
#define IO_TIMEOUT_S 15
#define GOOD_S       60 /* sessao que durou isso ja foi sucesso: volta logo */
#define RX_MAX       (65536 + 16)

static tls_conn conn;
static uint8_t rx[RX_MAX], dgram[65536], out[65536 + 14];

static int send_frame(int op, const uint8_t *p, size_t n)
{
	return tls_write(&conn, out, ws_frame(out, op, p, n));
}

static int open_udp(unsigned port)
{
	long fd = x_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	static const uint8_t lo[4] = { 127, 0, 0, 1 };
	struct sockaddr_in a;
	addr4(&a, lo, port);
	if (x_bind((int)fd, &a) < 0) return -1;
	return (int)fd;
}

static const char *session(int udp)
{
	uint8_t ip[4];
	struct sockaddr_in srv;
	if (dns_resolve(SERVER_HOST, ip)) return "wsudp: dns falhou";
	addr4(&srv, ip, 443);
	int fd = tcp_open(&srv, IO_TIMEOUT_S);
	if (fd < 0) return "wsudp: conexao recusada ou sem rota";
	const char *err = tls_handshake(&conn, fd, TLS_NAME, pinned_cert, sizeof pinned_cert,
	                                pinned_key, x_now() + 2 * IO_TIMEOUT_S);
	if (err) {
		x_log(err);
		err = "wsudp: tls";
		goto out;
	}

	/* upgrade HTTP -> WebSocket, com o destino no JWT */
	static char req[768];
	long n = ws_request(req, sizeof req, PATH, TLS_NAME,
	                    "\",\"p\":{\"Udp\":{\"timeout\":null}},\"r\":\"127.0.0.1\",\"rp\":51820}");
	err = "wsudp: escrita";
	if (n < 0 || tls_write(&conn, (const uint8_t *)req, (size_t)n)) goto out;

	/* resposta: precisa ser 101; o que vier depois ja e WebSocket */
	size_t rx_len = 0, end = 0;
	err = "wsudp: sem resposta ao upgrade";
	while (!end) {
		if (rx_len == RX_MAX) goto out;
		long r = tls_read(&conn, rx + rx_len, RX_MAX - rx_len); /* cada leitura tem prazo */
		if (r < 0) goto out;
		rx_len += (size_t)r;
		for (size_t i = 0; i + 4 <= rx_len && !end; i++)
			if (rx[i] == '\r' && rx[i + 1] == '\n' && rx[i + 2] == '\r' && rx[i + 3] == '\n') end = i + 4;
	}
	static const char ok[] = "HTTP/1.1 101";
	for (size_t i = 0; i < sizeof ok - 1; i++)
		if (i >= rx_len || rx[i] != (uint8_t)ok[i]) {
			err = "wsudp: upgrade recusado";
			goto out;
		}
	rx_len -= end;
	for (size_t i = 0; i < rx_len; i++) rx[i] = rx[end + i];
	x_log("wsudp: tunel aberto");

	struct sockaddr_in peer;
	int have_peer = 0;
	long last_rx = x_now(), last_ping = x_now();
	for (;;) {
		/* quadros completos ja recebidos */
		for (;;) {
			int op;
			size_t off, pl;
			long t = ws_parse(rx, rx_len, RX_MAX, &op, &off, &pl);
			err = "wsudp: quadro invalido";
			if (t < 0) goto out;
			if (t == 0) break;
			if (op == 2 && have_peer) x_sendto(udp, rx + off, pl, &peer);
			err = "wsudp: escrita";
			if (op == 9 && (pl > 125 || send_frame(0xA, rx + off, pl))) goto out;
			err = "wsudp: servidor fechou";
			if (op == 8) goto out;
			rx_len -= (size_t)t;
			for (size_t i = 0; i < rx_len; i++) rx[i] = rx[t + i];
		}

		struct pollfd fds[2] = { { .fd = udp, .events = POLLIN }, { .fd = fd, .events = POLLIN } };
		if (x_poll(fds, 2, tls_pending(&conn) ? 0 : 5000) < 0) continue;

		if (fds[0].revents & POLLIN) {
			/* varios datagramas por volta, sem bloquear */
			for (int k = 0; k < 16; k++) {
				struct sockaddr_in from;
				long m = x_recvfrom(udp, dgram, sizeof dgram, MSG_DONTWAIT, &from);
				if (m < 0) break;
				peer = from;
				have_peer = 1;
				err = "wsudp: escrita";
				if (send_frame(2, dgram, (size_t)m)) goto out;
			}
		}
		if (fds[1].revents || tls_pending(&conn)) {
			err = "wsudp: servidor fechou";
			if (rx_len == RX_MAX) goto out;
			long r = tls_read(&conn, rx + rx_len, RX_MAX - rx_len);
			if (r < 0) goto out;
			rx_len += (size_t)r;
			last_rx = x_now();
		}

		/* ping sempre; sem nada recebido ha muito, morta */
		long t = x_now();
		err = "wsudp: sem resposta do servidor";
		if (t - last_rx > DEAD_S) goto out;
		if (t - last_ping >= PING_S) {
			last_ping = t;
			err = "wsudp: escrita";
			if (send_frame(9, 0, 0)) goto out;
		}
	}
out:
	x_close(fd);
	return err;
}

int main(int argc, char **argv)
{
	unsigned port = argc > 1 ? atou(argv[1]) : 51820;
	int udp = open_udp(port ? port : 51820);
	if (udp < 0) {
		x_log("wsudp: porta udp local ocupada");
		return 1;
	}
	x_log("wsudp: udp local -> wss://" SERVER_HOST PATH);
	long backoff = 2;
	for (;;) {
		long t0 = x_now();
		x_log(session(udp));
		/* caiu depois de funcionar: volta logo; senao espera crescente ate 60 s */
		if (x_now() - t0 >= GOOD_S) backoff = 2;
		x_sleep((unsigned)backoff);
		backoff = backoff * 2 > 60 ? 60 : backoff * 2;
	}
}
