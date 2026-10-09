/* ntun-server: lado da VPS. Aceita os roteadores na porta 8222 (Noise_IK),
 * so com chave autorizada, e abre 127.0.0.1:<porta> de cada um: quem conecta
 * ali e ligado a uma conexao em espera daquele roteador.
 *
 * Uso: ntun-server [diretorio] [porta]       (padrao /etc/ntun 8222)
 *      ntun-server keygen                    (imprime: privada publica, em hex)
 *
 * <diretorio>/server.key  chave privada X25519 do servidor (hex)
 * <diretorio>/clients     uma linha por roteador: <chave-publica-hex> <porta> [nome]
 *                         (# comenta; mudou o arquivo: reiniciar o servico)
 *
 * Uma thread, poll(). Leituras sem bloquear; escritas com prazo (SNDTIMEO). */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/random.h>
#include <sys/socket.h>
#include "noise.h"
#include "proto.h"

#define MAX_CLIENTS     64
#define MAX_LINKS       256
#define MAX_PENDING     4   /* conexoes em espera por roteador */
#define SERVER_DEAD_S   90  /* o roteador pinga a cada 25 s */
#define USER_TIMEOUT_S  15

enum { L_FREE, L_HS, L_WAIT_READY, L_PENDING, L_ACTIVE };

struct client {
	uint8_t pub[32];
	unsigned port;
	char name[40];
	int lfd;
};

struct link {
	int state, fd, user, client;
	noise_cipher tx, rx;
	long since, last_rx;
	size_t in_len;
	uint8_t in[FRAME_MAX];
};

static struct client clients[MAX_CLIENTS];
static int nclients;
static struct link links[MAX_LINKS];
static uint8_t server_priv[32];
static uint8_t frame[FRAME_MAX], clear[MSG_MAX];

static long now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long)t.tv_sec;
}

static void logf_(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
static void logf_(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static int unhex32(uint8_t out[32], const char *h)
{
	for (int i = 0; i < 32; i++) {
		unsigned v;
		if (sscanf(h + 2 * i, "%2x", &v) != 1) return -1;
		out[i] = (uint8_t)v;
	}
	return 0;
}

static void hex32(char out[65], const uint8_t in[32])
{
	for (int i = 0; i < 32; i++) sprintf(out + 2 * i, "%02x", in[i]);
}

static void set_sndtimeo(int fd, long s)
{
	struct timeval tv = { s, 0 };
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static int write_all(int fd, const uint8_t *b, size_t n)
{
	while (n) {
		ssize_t r = write(fd, b, n);
		if (r < 0 && errno == EINTR) continue;
		if (r <= 0) return -1;
		b += r;
		n -= (size_t)r;
	}
	return 0;
}

static int listen_on(uint32_t ip, unsigned port)
{
	int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
	struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = ip };
	if (bind(fd, (struct sockaddr *)&a, sizeof a) || listen(fd, 16)) {
		close(fd);
		return -1;
	}
	return fd;
}

static int send_msg(struct link *l, int type, const uint8_t *d, size_t n)
{
	clear[0] = (uint8_t)type;
	memcpy(clear + 1, d, n);
	size_t m = noise_encrypt(&l->tx, clear, 1 + n, frame + 2);
	frame[0] = (uint8_t)(m >> 8);
	frame[1] = (uint8_t)m;
	return write_all(l->fd, frame, 2 + m);
}

static const char *cname(const struct link *l)
{
	return l->client >= 0 ? clients[l->client].name : "?";
}

static void link_close(struct link *l, const char *why)
{
	if (l->state == L_FREE) return;
	if (why) logf_("ntun-server: %s: %s", cname(l), why);
	if (l->user >= 0) close(l->user);
	close(l->fd);
	noise_wipe(&l->tx, sizeof l->tx);
	noise_wipe(&l->rx, sizeof l->rx);
	l->state = L_FREE;
	l->user = -1;
}

/* 1a mensagem do roteador: autentica a chave e responde */
static int on_handshake(struct link *l, const uint8_t *msg, size_t m)
{
	noise_hs hs;
	uint8_t payload[MSG_MAX], e[32], resp[NOISE_MSG2_LEN(0)];
	noise_ik_init(&hs, 0, server_priv, 0, (const uint8_t *)NTUN_PROLOGUE, sizeof NTUN_PROLOGUE - 1);
	long n = noise_ik_read1(&hs, msg, m, payload);
	if (n < 1 || payload[0] != NTUN_VERSION) {
		noise_wipe(&hs, sizeof hs);
		return -1;
	}
	l->client = -1;
	for (int i = 0; i < nclients; i++)
		if (memcmp(clients[i].pub, hs.rs, 32) == 0) l->client = i;
	if (l->client < 0) {
		char h[65];
		hex32(h, hs.rs);
		logf_("ntun-server: chave nao autorizada: %s", h);
		noise_wipe(&hs, sizeof hs);
		return -1;
	}
	if (getrandom(e, 32, 0) != 32) {
		noise_wipe(&hs, sizeof hs);
		return -1;
	}
	n = noise_ik_write2(&hs, e, 0, 0, resp, &l->tx, &l->rx);
	noise_wipe(&hs, sizeof hs);
	noise_wipe(e, sizeof e);
	if (n < 0) return -1;
	frame[0] = (uint8_t)(n >> 8);
	frame[1] = (uint8_t)n;
	memcpy(frame + 2, resp, (size_t)n);
	if (write_all(l->fd, frame, 2 + (size_t)n)) return -1;
	l->state = L_WAIT_READY;
	return 0;
}

static void on_ready(struct link *l)
{
	/* no maximo MAX_PENDING em espera por roteador: fecha a mais velha */
	int count = 0;
	struct link *oldest = 0;
	for (int i = 0; i < MAX_LINKS; i++) {
		struct link *o = &links[i];
		if (o->state != L_PENDING || o->client != l->client) continue;
		count++;
		if (!oldest || o->since < oldest->since) oldest = o;
	}
	if (count >= MAX_PENDING) link_close(oldest, 0);
	l->state = L_PENDING;
	l->since = now();
}

/* quadros completos de um roteador; -1 = link fechado */
static int on_frames(struct link *l)
{
	while (l->in_len >= 2) {
		size_t m = (size_t)l->in[0] << 8 | l->in[1];
		if (m > MSG_MAX || m < 1 + NOISE_TAG) { link_close(l, "quadro invalido"); return -1; }
		if (l->in_len < 2 + m) return 0;
		if (l->state == L_HS) {
			if (on_handshake(l, l->in + 2, m)) { link_close(l, 0); return -1; }
		} else {
			long n = noise_decrypt(&l->rx, l->in + 2, m, clear);
			if (n < 1) { link_close(l, "mensagem adulterada"); return -1; }
			int t = clear[0];
			if (l->state == L_WAIT_READY) {
				if (t != T_READY) { link_close(l, "sem READY"); return -1; }
				on_ready(l);
			} else if (t == T_PING) {
				if (send_msg(l, T_PONG, 0, 0)) { link_close(l, "escrita"); return -1; }
			} else if (t == T_CLOSE) {
				link_close(l, 0);
				return -1;
			} else if (t == T_DATA && l->state == L_ACTIVE) {
				if (write_all(l->user, clear + 1, (size_t)n - 1)) {
					send_msg(l, T_CLOSE, 0, 0);
					link_close(l, 0);
					return -1;
				}
			}
		}
		l->in_len -= 2 + m;
		memmove(l->in, l->in + 2 + m, l->in_len);
	}
	return 0;
}

static int load_config(const char *dir)
{
	char path[512], line[512];
	snprintf(path, sizeof path, "%s/server.key", dir);
	FILE *f = fopen(path, "r");
	if (!f || !fgets(line, sizeof line, f) || unhex32(server_priv, line)) {
		logf_("ntun-server: %s ausente ou invalida", path);
		if (f) fclose(f);
		return -1;
	}
	fclose(f);
	snprintf(path, sizeof path, "%s/clients", dir);
	f = fopen(path, "r");
	if (!f) {
		logf_("ntun-server: %s ausente", path);
		return -1;
	}
	while (fgets(line, sizeof line, f) && nclients < MAX_CLIENTS) {
		char key[80] = "", name[40] = "";
		unsigned port = 0;
		if (line[0] == '#' || sscanf(line, "%79s %u %39s", key, &port, name) < 2) continue;
		struct client *c = &clients[nclients];
		if (strlen(key) != 64 || unhex32(c->pub, key) || port == 0 || port > 65535) {
			logf_("ntun-server: linha invalida em clients: %s", line);
			continue;
		}
		c->port = port;
		snprintf(c->name, sizeof c->name, "%.39s", name[0] ? name : key);
		c->lfd = listen_on(htonl(INADDR_LOOPBACK), port);
		if (c->lfd < 0) {
			logf_("ntun-server: %s: porta 127.0.0.1:%u ocupada", c->name, port);
			continue;
		}
		nclients++;
	}
	fclose(f);
	return 0;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "keygen") == 0) {
		uint8_t priv[32], pub[32];
		char a[65], b[65];
		if (getrandom(priv, 32, 0) != 32) return 1;
		noise_public_key(pub, priv);
		hex32(a, priv);
		hex32(b, pub);
		printf("%s %s\n", a, b);
		return 0;
	}
	const char *dir = argc > 1 ? argv[1] : "/etc/ntun";
	unsigned port = argc > 2 ? (unsigned)atoi(argv[2]) : NTUN_DEFAULT_PORT;
	signal(SIGPIPE, SIG_IGN);
	if (load_config(dir)) return 1;
	int lfd = listen_on(htonl(INADDR_ANY), port);
	if (lfd < 0) {
		logf_("ntun-server: porta %u ocupada", port);
		return 1;
	}
	for (int i = 0; i < MAX_LINKS; i++) links[i].state = L_FREE, links[i].user = -1;
	logf_("ntun-server: porta %u, %d roteador(es)", port, nclients);

	static struct pollfd fds[1 + MAX_CLIENTS + 2 * MAX_LINKS];
	static int what[1 + MAX_CLIENTS + 2 * MAX_LINKS];
	static uint8_t buf[DATA_MAX];
	for (;;) {
		unsigned n = 0;
		fds[n] = (struct pollfd){ .fd = lfd, .events = POLLIN };
		what[n++] = -1;
		for (int i = 0; i < nclients; i++) {
			fds[n] = (struct pollfd){ .fd = clients[i].lfd, .events = POLLIN };
			what[n++] = 1000000 + i;
		}
		for (int i = 0; i < MAX_LINKS; i++) {
			if (links[i].state == L_FREE) continue;
			fds[n] = (struct pollfd){ .fd = links[i].fd, .events = POLLIN };
			what[n++] = i;
			if (links[i].state == L_ACTIVE) {
				fds[n] = (struct pollfd){ .fd = links[i].user, .events = POLLIN };
				what[n++] = 2000000 + i;
			}
		}
		if (poll(fds, n, 5000) < 0 && errno != EINTR) return 1;

		for (unsigned k = 0; k < n; k++) {
			if (!fds[k].revents) continue;
			int w = what[k];
			if (w == -1) {
				/* roteador chegando */
				int fd = accept4(lfd, 0, 0, SOCK_CLOEXEC);
				if (fd < 0) continue;
				struct link *l = 0;
				for (int i = 0; i < MAX_LINKS && !l; i++)
					if (links[i].state == L_FREE) l = &links[i];
				if (!l) { close(fd); continue; }
				set_sndtimeo(fd, 5);
				int one = 1;
				setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
				*l = (struct link){ .state = L_HS, .fd = fd, .user = -1, .client = -1 };
				l->since = l->last_rx = now();
			} else if (w >= 1000000 && w < 2000000) {
				/* alguem conectou na porta de um roteador */
				struct client *c = &clients[w - 1000000];
				int ufd = accept4(c->lfd, 0, 0, SOCK_CLOEXEC);
				if (ufd < 0) continue;
				struct link *best = 0;
				for (int i = 0; i < MAX_LINKS; i++) {
					struct link *l = &links[i];
					if (l->state == L_PENDING && l->client == w - 1000000 && (!best || l->last_rx > best->last_rx))
						best = l;
				}
				if (!best) {
					logf_("ntun-server: %s: sem conexao em espera", c->name);
					close(ufd);
					continue;
				}
				set_sndtimeo(ufd, USER_TIMEOUT_S);
				best->user = ufd;
				best->state = L_ACTIVE;
				if (send_msg(best, T_GO, 0, 0)) link_close(best, "escrita");
			} else if (w >= 2000000) {
				struct link *l = &links[w - 2000000];
				if (l->state != L_ACTIVE) continue;
				ssize_t r = recv(l->user, buf, sizeof buf, MSG_DONTWAIT);
				if (r < 0 && (errno == EAGAIN || errno == EINTR)) continue;
				if (r <= 0 || send_msg(l, T_DATA, buf, (size_t)r)) {
					send_msg(l, T_CLOSE, 0, 0);
					link_close(l, 0);
				}
			} else {
				struct link *l = &links[w];
				if (l->state == L_FREE) continue;
				ssize_t r = recv(l->fd, l->in + l->in_len, sizeof l->in - l->in_len, MSG_DONTWAIT);
				if (r < 0 && (errno == EAGAIN || errno == EINTR)) continue;
				if (r <= 0) { link_close(l, l->state >= L_PENDING ? "roteador desconectou" : 0); continue; }
				l->in_len += (size_t)r;
				l->last_rx = now();
				on_frames(l);
			}
		}

		/* prazos: handshake parado, roteador sem pingar */
		long t = now();
		for (int i = 0; i < MAX_LINKS; i++) {
			struct link *l = &links[i];
			if (l->state == L_FREE) continue;
			if ((l->state == L_HS || l->state == L_WAIT_READY) && t - l->since > HANDSHAKE_S)
				link_close(l, 0);
			else if (t - l->last_rx > SERVER_DEAD_S)
				link_close(l, "sem resposta");
		}
	}
}
