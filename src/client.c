/* ntun: cliente do roteador. Tunel reverso TCP cifrado com Noise_IK ate a
 * VPS: quem conecta em 127.0.0.1:<porta do roteador> na VPS chega em
 * 127.0.0.1:<porta local> do roteador (ssh/telnet/web).
 *
 * Uso: ntun [porta-local] [arquivo-chave] [servidor] [porta] [chave-publica-do-servidor]
 *   porta-local      22
 *   arquivo-chave    /etc/ntun.key (chave privada X25519 em hex, 64 caracteres)
 *   servidor, porta  br.rotava.com 8222
 *   chave publica    a de server_pub.h (hex; so para testes)
 *
 * Uma thread, poll(); ate MAX_SESS sessoes, sempre uma conexao em espera.
 * Prazo em toda operacao bloqueante, keepalive TCP, ping a cada 25 s,
 * conexao sem resposta derrubada, espera crescente ate 60 s. */
#include "sys.h"
#include "noise.h"
#include "proto.h"
#include "server_pub.h"
#include "util.h"

#ifndef NTUN_HOST
#define NTUN_HOST "br.rotava.com"
#endif

#define MAX_SESS     4
#define QUICK_FAIL_S 10 /* conexao em espera que morre antes disso foi recusada */

enum { FREE, PENDING, ACTIVE };

struct sess {
	int state, net, local;
	noise_cipher tx, rx;
	long since, last_rx, last_ping;
	size_t in_len;
	uint8_t in[FRAME_MAX];
};

static struct sess sess[MAX_SESS];
static uint8_t my_key[32], srv_key[32];
static const char *host = NTUN_HOST;
static unsigned srv_port = NTUN_DEFAULT_PORT, local_port = 22;
static struct sockaddr_in srv;
static int have_srv;
static long backoff = 2, next_try;
static uint8_t frame[FRAME_MAX], clear[MSG_MAX];

/* ------------------------------------------------------------- sessoes */

static int send_msg(struct sess *s, int type, const uint8_t *d, size_t n)
{
	clear[0] = (uint8_t)type;
	for (size_t i = 0; i < n; i++) clear[1 + i] = d[i];
	size_t m = noise_encrypt(&s->tx, clear, 1 + n, frame + 2);
	frame[0] = (uint8_t)(m >> 8);
	frame[1] = (uint8_t)m;
	return write_all(s->net, frame, 2 + m);
}

static void sess_close(struct sess *s)
{
	if (s->state == FREE) return;
	if (s->local >= 0) x_close(s->local);
	x_close(s->net);
	noise_wipe(&s->tx, sizeof s->tx);
	noise_wipe(&s->rx, sizeof s->rx);
	s->local = -1;
	s->state = FREE;
}

/* falha de uma sessao; conexao em espera recusada logo entra na espera crescente */
static void sess_fail(struct sess *s, const char *why)
{
	if (why) x_log(why);
	if (s->state == PENDING) {
		if (x_now() - s->since < QUICK_FAIL_S) {
			next_try = x_now() + backoff;
			backoff = backoff * 2 > 60 ? 60 : backoff * 2;
		} else {
			backoff = 2;
		}
	}
	sess_close(s);
}

/* TCP + handshake + READY; bloqueante, com prazos */
static const char *open_link(struct sess *s)
{
	static const char *const proto_prologue = NTUN_PROLOGUE;
	if (!have_srv) {
		uint8_t ip[4];
		if (dns_resolve(host, ip)) return "ntun: dns falhou";
		addr4(&srv, ip, srv_port);
		have_srv = 1;
	}
	s->net = tcp_open(&srv, IO_TIMEOUT_S);
	s->local = -1;
	if (s->net < 0) return "ntun: conexao recusada ou sem rota";
	const char *err;

	long deadline = x_now() + HANDSHAKE_S;
	noise_hs hs;
	uint8_t e[32], msg[NOISE_MSG1_LEN(1)], ver = NTUN_VERSION;
	err = "ntun: sem aleatorio";
	if (random_bytes(e, 32)) goto fail;
	noise_ik_init(&hs, 1, my_key, srv_key, (const uint8_t *)proto_prologue, sizeof NTUN_PROLOGUE - 1);
	err = "ntun: handshake";
	long n = noise_ik_write1(&hs, e, &ver, 1, msg);
	noise_wipe(e, sizeof e);
	if (n < 0) goto fail_hs;
	frame[0] = (uint8_t)(n >> 8);
	frame[1] = (uint8_t)n;
	for (long i = 0; i < n; i++) frame[2 + i] = msg[i];
	if (write_all(s->net, frame, 2 + (size_t)n)) goto fail_hs;

	/* resposta: so a 2a mensagem (sem payload); servidor que nao conhece
	 * a nossa chave so fecha */
	uint8_t hdr[2], resp[NOISE_MSG2_LEN(0)], none[1];
	err = "ntun: servidor fechou no handshake (chave nao autorizada?)";
	if (read_all(s->net, hdr, 2, deadline)) goto fail_hs;
	err = "ntun: handshake";
	if (((unsigned)hdr[0] << 8 | hdr[1]) != sizeof resp) goto fail_hs;
	if (read_all(s->net, resp, sizeof resp, deadline)) goto fail_hs;
	err = "ntun: servidor nao e o esperado (handshake recusado)";
	if (noise_ik_read2(&hs, resp, sizeof resp, none, &s->tx, &s->rx) < 0) goto fail_hs;
	noise_wipe(&hs, sizeof hs);

	err = "ntun: escrita";
	if (send_msg(s, T_READY, 0, 0)) goto fail;
	s->state = PENDING;
	s->in_len = 0;
	s->since = s->last_rx = s->last_ping = x_now();
	return 0;

fail_hs:
	noise_wipe(&hs, sizeof hs);
fail:
	x_close(s->net);
	return err;
}

static int go_local(struct sess *s)
{
	long fd = x_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	/* servico local que para de ler nao trava as outras sessoes */
	set_timeout((int)fd, SO_SNDTIMEO, IO_TIMEOUT_S);
	static const uint8_t lo[4] = { 127, 0, 0, 1 };
	struct sockaddr_in a;
	addr4(&a, lo, local_port);
	if (x_connect((int)fd, &a) < 0) {
		x_close((int)fd);
		return -1;
	}
	s->local = (int)fd;
	s->state = ACTIVE;
	backoff = 2;
	return 0;
}

/* quadros completos ja recebidos; -1 = sessao acabou */
static int on_frames(struct sess *s)
{
	while (s->in_len >= 2) {
		size_t m = (size_t)s->in[0] << 8 | s->in[1];
		if (m > MSG_MAX || m < 1 + NOISE_TAG) { sess_fail(s, "ntun: quadro invalido"); return -1; }
		if (s->in_len < 2 + m) return 0;
		long n = noise_decrypt(&s->rx, s->in + 2, m, clear);
		if (n < 1) { sess_fail(s, "ntun: mensagem adulterada"); return -1; }
		switch (clear[0]) {
		case T_GO:
			if (s->state != PENDING || go_local(s)) {
				send_msg(s, T_CLOSE, 0, 0);
				sess_fail(s, "ntun: servico local nao responde");
				return -1;
			}
			break;
		case T_DATA:
			if (s->state != ACTIVE || write_all(s->local, clear + 1, (size_t)n - 1)) {
				send_msg(s, T_CLOSE, 0, 0);
				sess_close(s);
				return -1;
			}
			break;
		case T_CLOSE:
			sess_close(s);
			return -1;
		case T_PING:
			if (send_msg(s, T_PONG, 0, 0)) { sess_fail(s, 0); return -1; }
			break;
		default: /* PONG e desconhecidos */
			break;
		}
		s->in_len -= 2 + m;
		for (size_t i = 0; i < s->in_len; i++) s->in[i] = s->in[2 + m + i];
	}
	return 0;
}

static int load_key(const char *path)
{
	char h[70];
	long fd = x_open(path);
	if (fd < 0) return -1;
	long n = x_read((int)fd, h, sizeof h - 1);
	x_close((int)fd);
	if (n < 64) return -1;
	return unhex32(my_key, h);
}

int main(int argc, char **argv)
{
	const char *key_path = "/etc/ntun.key";
	if (argc > 1) local_port = atou(argv[1]);
	if (argc > 2) key_path = argv[2];
	if (argc > 3) host = argv[3];
	if (argc > 4) srv_port = atou(argv[4]);
	for (int i = 0; i < 32; i++) srv_key[i] = server_pub[i];
	if (argc > 5 && unhex32(srv_key, argv[5])) { x_log("ntun: chave do servidor invalida"); return 1; }
	if (load_key(key_path)) { x_log("ntun: chave invalida ou ausente (hex de 64 caracteres)"); return 1; }
	for (int i = 0; i < MAX_SESS; i++) sess[i].local = -1;
	x_log("ntun: iniciado");

	static uint8_t buf[DATA_MAX];
	for (;;) {
		long t = x_now();

		/* sempre uma conexao em espera, se houver vaga */
		struct sess *pending = 0, *free = 0;
		for (int i = 0; i < MAX_SESS; i++) {
			if (sess[i].state == PENDING) pending = &sess[i];
			if (sess[i].state == FREE && !free) free = &sess[i];
		}
		if (!pending && free && t >= next_try) {
			const char *err = open_link(free);
			if (err) {
				x_log(err);
				have_srv = 0; /* refaz o DNS na proxima */
				next_try = t + backoff;
				backoff = backoff * 2 > 60 ? 60 : backoff * 2;
			}
		}

		struct pollfd fds[MAX_SESS * 2];
		int idx[MAX_SESS * 2];
		unsigned nf = 0;
		for (int i = 0; i < MAX_SESS; i++) {
			if (sess[i].state == FREE) continue;
			fds[nf] = (struct pollfd){ .fd = sess[i].net, .events = POLLIN };
			idx[nf++] = i;
			if (sess[i].state == ACTIVE) {
				fds[nf] = (struct pollfd){ .fd = sess[i].local, .events = POLLIN };
				idx[nf++] = i + MAX_SESS;
			}
		}
		/* sem sessao (VPS fora): dorme ate a proxima tentativa */
		if (nf == 0) {
			x_sleep(next_try > t ? (unsigned)(next_try - t) : 1);
			continue;
		}
		if (x_poll(fds, nf, 5000) < 0) continue;

		for (unsigned k = 0; k < nf; k++) {
			if (!fds[k].revents) continue;
			struct sess *s = &sess[idx[k] % MAX_SESS];
			if (s->state == FREE) continue;
			if (idx[k] < MAX_SESS) {
				long r = x_read(s->net, s->in + s->in_len, sizeof s->in - s->in_len);
				if (r == -EINTR) continue;
				if (r <= 0) { sess_fail(s, 0); continue; }
				s->in_len += (size_t)r;
				s->last_rx = x_now();
				on_frames(s);
			} else if (s->state == ACTIVE) {
				long r = x_read(s->local, buf, sizeof buf);
				if (r == -EINTR) continue;
				if (r <= 0 || send_msg(s, T_DATA, buf, (size_t)r)) {
					send_msg(s, T_CLOSE, 0, 0);
					sess_close(s);
				}
			}
		}

		/* ping sempre; sem nada recebido ha muito, conexao morta */
		t = x_now();
		for (int i = 0; i < MAX_SESS; i++) {
			struct sess *s = &sess[i];
			if (s->state == FREE) continue;
			if (t - s->last_rx > DEAD_S) {
				sess_fail(s, "ntun: sem resposta da VPS");
			} else if (t - s->last_ping >= PING_S) {
				s->last_ping = t;
				if (send_msg(s, T_PING, 0, 0)) sess_fail(s, 0);
			}
		}
	}
}
