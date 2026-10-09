/* rtun (C): tunel reverso TCP por WSS (protocolo do wstunnel v10), porte do
 * rtun em Zig. O roteador abre wss://br.rotava.com/<prefixo>/events e pede
 * ao wstunnel da VPS para escutar em 127.0.0.1:<porta>; cada conexao ali vira
 * uma sessao para 127.0.0.1:<local> do roteador (telnet/ssh/web).
 *
 * Configuracao na compilacao: -DRTUN_PREFIX='"rev-..."' -DRTUN_PORT=22101
 * -DRTUN_LOCAL=22 (o prefixo secreto fica em /etc/wstunnel/rtun-prefix na VPS).
 *
 * TLS 1.3 so com o certificado Ed25519 fixado (cert.h); uma thread, poll();
 * sempre uma conexao em espera, ate MAX_SESS sessoes. */
#include "util.h"
#include "tls13.h"
#include "ws.h"
#include "cert.h"

#ifndef RTUN_PREFIX
#define RTUN_PREFIX "rev-CONFIGURE"
#endif
#ifndef RTUN_PORT
#define RTUN_PORT 22101
#endif
#ifndef RTUN_LOCAL
#define RTUN_LOCAL 23
#endif
#define STR2(x) #x
#define STR(x) STR2(x)

#define SERVER_HOST "br.rotava.com"
#define TLS_NAME    "wsudp.rotava.internal"
#define MAX_SESS    4
#define PENDING_REFRESH_S 240 /* NAT esquece TCP parado */
#define PING_S       25
#define DEAD_S       75
#define QUICK_FAIL_S 10
#define IO_TIMEOUT_S 15
#define RX_MAX       (65536 + 64)

enum { FREE, PENDING, ACTIVE };

struct sess {
	int state, local;
	long since, last_ping, last_rx;
	size_t rx_len;
	tls_conn tls;
	uint8_t rx[RX_MAX];
};

static struct sess sess[MAX_SESS];
static struct sockaddr_in srv;
static int have_srv;
static long backoff = 2, next_try;
static uint8_t out[16384 + 14], buf[16384];

static int send_frame(struct sess *s, int op, const uint8_t *p, size_t n)
{
	return tls_write(&s->tls, out, ws_frame(out, op, p, n));
}

static void sess_close(struct sess *s)
{
	if (s->state == FREE) return;
	if (s->local >= 0) x_close(s->local);
	x_close(s->tls.fd);
	s->local = -1;
	s->state = FREE;
}

static void sess_fail(struct sess *s, const char *why)
{
	if (why) x_log(why);
	if (s->state == PENDING) {
		/* recusada logo (prefixo, porta ocupada...): sem laco apertado */
		if (x_now() - s->since < QUICK_FAIL_S) {
			next_try = x_now() + backoff;
			backoff = backoff * 2 > 60 ? 60 : backoff * 2;
		} else {
			backoff = 2;
		}
	}
	sess_close(s);
}

/* TCP + TLS + pedido de upgrade; a resposta (101) so vem quando alguem
 * conectar na porta da VPS */
static const char *open_pending(struct sess *s)
{
	if (!have_srv) {
		uint8_t ip[4];
		if (dns_resolve(SERVER_HOST, ip)) return "rtun: dns falhou";
		addr4(&srv, ip, 443);
		have_srv = 1;
	}
	int fd = tcp_open(&srv, IO_TIMEOUT_S);
	if (fd < 0) return "rtun: conexao recusada ou sem rota";
	const char *err = tls_handshake(&s->tls, fd, TLS_NAME, pinned_cert, sizeof pinned_cert,
	                                pinned_key, x_now() + 2 * IO_TIMEOUT_S);
	if (err) {
		x_close(fd);
		x_log(err);
		return "rtun: tls";
	}
	static char req[768];
	long n = ws_request(req, sizeof req, "/" RTUN_PREFIX "/events", TLS_NAME,
	                    "\",\"p\":\"ReverseTcp\",\"r\":\"127.0.0.1\",\"rp\":" STR(RTUN_PORT) "}");
	if (n < 0 || tls_write(&s->tls, (const uint8_t *)req, (size_t)n)) {
		x_close(fd);
		return "rtun: escrita";
	}
	s->state = PENDING;
	s->local = -1;
	s->rx_len = 0;
	s->since = s->last_ping = s->last_rx = x_now();
	return 0;
}

static int starts(const uint8_t *b, size_t n, const char *p)
{
	for (size_t i = 0; p[i]; i++)
		if (i >= n || b[i] != (uint8_t)p[i]) return 0;
	return 1;
}

/* dados do socket da VPS; -1 = sessao acabou */
static int on_net(struct sess *s)
{
	if (s->rx_len == RX_MAX) return -1;
	long r = tls_read(&s->tls, s->rx + s->rx_len, RX_MAX - s->rx_len);
	if (r < 0) return -1;
	s->rx_len += (size_t)r;
	s->last_rx = x_now();

	if (s->state == PENDING) {
		size_t end = 0;
		for (size_t i = 0; i + 4 <= s->rx_len && !end; i++)
			if (s->rx[i] == '\r' && s->rx[i + 1] == '\n' && s->rx[i + 2] == '\r' && s->rx[i + 3] == '\n') end = i + 4;
		if (!end) return 0;
		if (!starts(s->rx, s->rx_len, "HTTP/1.1 101")) {
			x_log("rtun: upgrade recusado");
			return -1;
		}
		s->rx_len -= end;
		for (size_t i = 0; i < s->rx_len; i++) s->rx[i] = s->rx[end + i];

		/* alguem conectou na VPS: liga ao servico local */
		long fd = x_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
		if (fd < 0) return -1;
		set_timeout((int)fd, SO_SNDTIMEO, IO_TIMEOUT_S); /* servico parado nao trava os outros */
		static const uint8_t lo[4] = { 127, 0, 0, 1 };
		struct sockaddr_in a;
		addr4(&a, lo, RTUN_LOCAL);
		if (x_connect((int)fd, &a) < 0) {
			x_close((int)fd);
			x_log("rtun: servico local nao responde");
			return -1;
		}
		s->local = (int)fd;
		s->state = ACTIVE;
		s->last_ping = x_now();
		backoff = 2;
	}

	/* quadros completos do servidor */
	for (;;) {
		int op;
		size_t off, n;
		long t = ws_parse(s->rx, s->rx_len, RX_MAX, &op, &off, &n);
		if (t < 0) return -1;
		if (t == 0) return 0;
		if (op == 0 || op == 2) {
			if (write_all(s->local, s->rx + off, n)) return -1;
		} else if (op == 9) {
			if (n > 125 || send_frame(s, 0xA, s->rx + off, n)) return -1;
		} else if (op == 8) {
			return -1;
		}
		s->rx_len -= (size_t)t;
		for (size_t i = 0; i < s->rx_len; i++) s->rx[i] = s->rx[t + i];
	}
}

int main(void)
{
	x_log("rtun: " SERVER_HOST " -> vps 127.0.0.1:" STR(RTUN_PORT) " = local 127.0.0.1:" STR(RTUN_LOCAL));
	for (int i = 0; i < MAX_SESS; i++) sess[i].local = -1;

	for (;;) {
		long t = x_now();
		struct sess *pending = 0, *avail = 0;
		for (int i = 0; i < MAX_SESS; i++) {
			if (sess[i].state == PENDING) pending = &sess[i];
			if (sess[i].state == FREE && !avail) avail = &sess[i];
		}
		if (pending && t - pending->since > PENDING_REFRESH_S) {
			sess_close(pending);
			if (!avail) avail = pending;
			pending = 0;
		}
		if (!pending && avail && t >= next_try) {
			const char *err = open_pending(avail);
			if (err) {
				x_log(err);
				have_srv = 0; /* refaz o DNS */
				next_try = t + backoff;
				backoff = backoff * 2 > 60 ? 60 : backoff * 2;
			}
		}

		struct pollfd fds[MAX_SESS * 2];
		int idx[MAX_SESS * 2];
		unsigned nf = 0;
		int timeout = 5000;
		for (int i = 0; i < MAX_SESS; i++) {
			if (sess[i].state == FREE) continue;
			fds[nf] = (struct pollfd){ .fd = sess[i].tls.fd, .events = POLLIN };
			idx[nf++] = i;
			if (sess[i].state == ACTIVE) {
				fds[nf] = (struct pollfd){ .fd = sess[i].local, .events = POLLIN };
				idx[nf++] = i + MAX_SESS;
			}
			if (tls_pending(&sess[i].tls)) timeout = 0;
		}
		if (nf == 0) {
			x_sleep(next_try > t ? (unsigned)(next_try - t) : 1);
			continue;
		}
		if (x_poll(fds, nf, timeout) < 0) continue;

		for (int i = 0; i < MAX_SESS; i++) {
			struct sess *s = &sess[i];
			if (s->state == FREE) continue;
			int net = tls_pending(&s->tls), loc = 0;
			for (unsigned k = 0; k < nf; k++) {
				if (!fds[k].revents) continue;
				if (idx[k] == i) net = 1;
				if (idx[k] == i + MAX_SESS) loc = 1;
			}
			if (net && on_net(s)) {
				sess_fail(s, 0);
				continue;
			}
			if (loc && s->state == ACTIVE) {
				long r = x_read(s->local, buf, sizeof buf);
				if (r == -EINTR) continue;
				if (r <= 0 || send_frame(s, 2, buf, (size_t)r)) {
					send_frame(s, 8, 0, 0);
					sess_close(s);
				}
			}
		}

		/* ping sempre; sem nada recebido ha muito, morta */
		t = x_now();
		for (int i = 0; i < MAX_SESS; i++) {
			struct sess *s = &sess[i];
			if (s->state != ACTIVE) continue;
			if (t - s->last_rx > DEAD_S) {
				sess_fail(s, "rtun: sessao sem resposta");
			} else if (t - s->last_ping >= PING_S) {
				s->last_ping = t;
				if (send_frame(s, 9, 0, 0)) sess_fail(s, 0);
			}
		}
	}
}
