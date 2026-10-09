/* Pecas comuns dos clientes; ver util.h */
#include "util.h"

int hexval(char c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

int unhex32(uint8_t out[32], const char *h)
{
	for (int i = 0; i < 32; i++) {
		int a = hexval(h[2 * i]), b = a < 0 ? -1 : hexval(h[2 * i + 1]);
		if (b < 0) return -1;
		out[i] = (uint8_t)(a << 4 | b);
	}
	return 0;
}

unsigned atou(const char *s)
{
	unsigned v = 0;
	while (*s >= '0' && *s <= '9') v = v * 10 + (unsigned)(*s++ - '0');
	return v;
}

void addr4(struct sockaddr_in *a, const uint8_t ip[4], unsigned port)
{
	uint8_t *p = (uint8_t *)a;
	for (unsigned i = 0; i < sizeof *a; i++) p[i] = 0;
	a->sin_family = AF_INET;
	p = (uint8_t *)&a->sin_port;
	p[0] = (uint8_t)(port >> 8);
	p[1] = (uint8_t)port;
	p = (uint8_t *)&a->sin_addr;
	for (int i = 0; i < 4; i++) p[i] = ip[i];
}

/* "a.b.c.d" */
int parse_ip4(uint8_t ip[4], const char *s)
{
	for (int i = 0; i < 4; i++) {
		if (*s < '0' || *s > '9') return -1;
		unsigned v = 0;
		while (*s >= '0' && *s <= '9') v = v * 10 + (unsigned)(*s++ - '0');
		if (v > 255 || (i < 3 && *s++ != '.')) return -1;
		ip[i] = (uint8_t)v;
	}
	return *s ? -1 : 0;
}

int random_bytes(uint8_t *b, size_t n)
{
	size_t o = 0;
	while (o < n) {
		long r = x_getrandom(b + o, n - o);
		if (r == -EINTR) continue;
		if (r <= 0) break;
		o += (size_t)r;
	}
	if (o == n) return 0;
	/* kernel sem getrandom */
	long fd = x_open("/dev/urandom");
	if (fd < 0) return -1;
	while (o < n) {
		long r = x_read((int)fd, b + o, n - o);
		if (r <= 0) break;
		o += (size_t)r;
	}
	x_close((int)fd);
	return o == n ? 0 : -1;
}

int write_all(int fd, const uint8_t *b, size_t n)
{
	while (n) {
		long r = x_write(fd, b, n);
		if (r == -EINTR) continue;
		if (r <= 0) return -1; /* inclui prazo esgotado (EAGAIN) */
		b += r;
		n -= (size_t)r;
	}
	return 0;
}

int read_all(int fd, uint8_t *b, size_t n, long deadline)
{
	while (n) {
		if (x_now() > deadline) return -1;
		long r = x_read(fd, b, n);
		if (r == -EINTR) continue;
		if (r <= 0) return -1;
		b += r;
		n -= (size_t)r;
	}
	return 0;
}

void set_timeout(int fd, int opt, long sec)
{
	long tv[2] = { sec, 0 }; /* struct timeval da ABI (long, long) */
	x_setsockopt(fd, SOL_SOCKET, opt, tv, sizeof tv);
}


int dns_resolve(const char *host, uint8_t ip[4])
{
	if (parse_ip4(ip, host) == 0) return 0;

	uint8_t ns[4] = { 127, 0, 0, 1 };
	long f = x_open("/etc/resolv.conf");
	if (f >= 0) {
		static char rc[1024];
		long n = x_read((int)f, rc, sizeof rc - 1);
		x_close((int)f);
		rc[n > 0 ? n : 0] = 0;
		for (char *l = rc; *l;) {
			char *e = l;
			while (*e && *e != '\n') e++;
			char c = *e;
			*e = 0;
			char *p = l;
			while (*p == ' ' || *p == '\t') p++;
			const char *kw = "nameserver";
			int k = 0;
			while (kw[k] && p[k] == kw[k]) k++;
			if (!kw[k]) {
				p += k;
				while (*p == ' ' || *p == '\t') p++;
				char *q = p;
				while (*q && *q != ' ' && *q != '\t' && *q != '\r') q++;
				*q = 0;
				if (parse_ip4(ns, p) == 0) break;
				ns[0] = 127, ns[1] = 0, ns[2] = 0, ns[3] = 1;
			}
			*e = c;
			l = c ? e + 1 : e;
		}
	}

	/* consulta: cabecalho + nome + A IN */
	uint8_t q[300];
	size_t qn = 12;
	if (random_bytes(q, 2)) return -1;
	q[2] = 1, q[3] = 0, q[4] = 0, q[5] = 1;
	for (int i = 6; i < 12; i++) q[i] = 0;
	for (const char *s = host; *s;) {
		const char *e = s;
		while (*e && *e != '.') e++;
		size_t l = (size_t)(e - s);
		if (l == 0 || l > 63 || qn + l + 6 > sizeof q) return -1;
		q[qn++] = (uint8_t)l;
		while (s < e) q[qn++] = (uint8_t)*s++;
		if (*s) s++;
	}
	q[qn++] = 0;
	q[qn++] = 0, q[qn++] = 1, q[qn++] = 0, q[qn++] = 1;

	long fd = x_socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	set_timeout((int)fd, SO_RCVTIMEO, 3);
	struct sockaddr_in to;
	addr4(&to, ns, 53);
	int ok = -1;
	for (int tries = 0; tries < 3 && ok < 0; tries++) {
		if (x_sendto((int)fd, q, qn, &to) < 0) continue;
		uint8_t r[512];
		long n = x_recv((int)fd, r, sizeof r, 0);
		if (n < 12 || r[0] != q[0] || r[1] != q[1] || (r[3] & 0x0f)) continue;
		unsigned an = (unsigned)r[6] << 8 | r[7];
		size_t i = qn; /* pula a pergunta (igual a nossa) */
		for (unsigned k = 0; k < an && i + 12 <= (size_t)n; k++) {
			if ((r[i] & 0xc0) == 0xc0) i += 2;
			else {
				while (i < (size_t)n && r[i]) i += (size_t)r[i] + 1;
				i++;
			}
			if (i + 10 > (size_t)n) break;
			unsigned typ = (unsigned)r[i] << 8 | r[i + 1];
			unsigned len = (unsigned)r[i + 8] << 8 | r[i + 9];
			i += 10;
			if (i + len > (size_t)n) break;
			if (typ == 1 && len == 4) {
				for (int j = 0; j < 4; j++) ip[j] = r[i + j];
				ok = 0;
				break;
			}
			i += len;
		}
		if (ok < 0) break; /* respondeu sem registro A */
	}
	x_close((int)fd);
	return ok;
}

int tcp_open(const struct sockaddr_in *a, long timeout_s)
{
	long fd = x_socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0) return -1;
	/* no Linux o SNDTIMEO vale tambem para o connect */
	set_timeout((int)fd, SO_SNDTIMEO, timeout_s);
	set_timeout((int)fd, SO_RCVTIMEO, timeout_s);
	/* keepalive: nota rota/NAT morto em ~1 min mesmo sem trafego */
	static const int opt[4][3] = {
		{ SOL_SOCKET, SO_KEEPALIVE, 1 },
		{ IPPROTO_TCP, TCP_KEEPIDLE, 30 },
		{ IPPROTO_TCP, TCP_KEEPINTVL, 10 },
		{ IPPROTO_TCP, TCP_KEEPCNT, 3 },
	};
	for (int i = 0; i < 4; i++) x_setsockopt((int)fd, opt[i][0], opt[i][1], &opt[i][2], sizeof(int));
	if (x_connect((int)fd, a) < 0) {
		x_close((int)fd);
		return -1;
	}
	return (int)fd;
}

size_t b64(char *out, const uint8_t *in, size_t n, int url)
{
	static const char std[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	size_t o = 0;
	for (size_t i = 0; i < n; i += 3) {
		size_t k = n - i < 3 ? n - i : 3;
		uint32_t v = (uint32_t)in[i] << 16;
		if (k > 1) v |= (uint32_t)in[i + 1] << 8;
		if (k > 2) v |= in[i + 2];
		for (size_t j = 0; j < 4; j++) {
			if (j <= k) {
				char ch = std[(v >> (18 - 6 * j)) & 63];
				if (url && ch == '+') ch = '-';
				if (url && ch == '/') ch = '_';
				out[o++] = ch;
			} else if (!url) {
				out[o++] = '=';
			}
		}
	}
	return o;
}
