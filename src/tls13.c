/* TLS 1.3 minimo; ver tls13.h */
#include "tls13.h"
#include "aead.h"
#include "c25519.h"
#include "sha2.h"
#include "sys.h"
#include "util.h"

static int write_all(int fd, const uint8_t *b, size_t n)
{
	while (n) {
		long r = x_write(fd, b, n);
		if (r == -EINTR) continue;
		if (r <= 0) return -1;
		b += r;
		n -= (size_t)r;
	}
	return 0;
}

static int read_full(int fd, uint8_t *b, size_t n)
{
	while (n) {
		long r = x_read(fd, b, n);
		if (r == -EINTR) continue;
		if (r <= 0) return -1;
		b += r;
		n -= (size_t)r;
	}
	return 0;
}

static void set_keys(uint8_t key[32], uint8_t iv[12], uint8_t sec[32], uint64_t *seq,
                     const uint8_t secret[32])
{
	for (int i = 0; i < 32; i++) sec[i] = secret[i];
	hkdf_label(key, secret, "key", 0, 0, 32);
	hkdf_label(iv, secret, "iv", 0, 0, 12);
	*seq = 0;
}

static void nonce(uint8_t n[12], const uint8_t iv[12], uint64_t seq)
{
	for (int i = 0; i < 12; i++) n[i] = iv[i];
	for (int i = 0; i < 8; i++) n[11 - i] ^= (uint8_t)(seq >> (8 * i));
}

/* cifra e manda um registro (tipo real dentro, como manda o TLS 1.3) */
static int seal(tls_conn *c, int typ, const uint8_t *d, size_t n)
{
	static uint8_t out[5 + TLS_MAX_PLAIN + 1 + 16];
	size_t cl = n + 1 + 16;
	uint8_t nn[12];
	out[0] = 23, out[1] = 3, out[2] = 3, out[3] = (uint8_t)(cl >> 8), out[4] = (uint8_t)cl;
	for (size_t i = 0; i < n; i++) out[5 + i] = d[i];
	out[5 + n] = (uint8_t)typ;
	nonce(nn, c->civ, c->cseq++);
	aead_seal(out + 5, c->ckey, nn, out, 5, out + 5, n + 1);
	return write_all(c->fd, out, 5 + cl);
}

/* le e decifra um registro (pula ChangeCipherSpec); tipo real em *typ,
 * texto em rec[5..5+*len]. -1 = erro/fim. */
static int open_rec(tls_conn *c, int *typ, size_t *len)
{
	for (;;) {
		if (read_full(c->fd, c->rec, 5)) return -1;
		size_t n = (size_t)c->rec[3] << 8 | c->rec[4];
		if (n > TLS_MAX_RECORD || read_full(c->fd, c->rec + 5, n)) return -1;
		if (c->rec[0] == 20) continue;      /* ChangeCipherSpec */
		if (c->rec[0] != 23 || n < 17) return -1; /* alerta em claro etc. */
		uint8_t nn[12];
		nonce(nn, c->siv, c->sseq);
		if (aead_open(c->rec + 5, c->skey, nn, c->rec, 5, c->rec + 5, n)) return -1;
		c->sseq++;
		size_t e = n - 16;
		while (e > 0 && c->rec[5 + e - 1] == 0) e--; /* preenchimento */
		if (e == 0) return -1;
		*typ = c->rec[5 + e - 1];
		*len = e - 1;
		return 0;
	}
}

/* junta mensagens de handshake, que podem vir quebradas entre registros */
typedef struct {
	uint8_t b[8192];
	size_t  n;
	long    deadline;
} hsbuf;

/* devolve o tamanho da proxima mensagem completa (cabecalho incluso) ou 0 */
static size_t hs_next(hsbuf *h, tls_conn *c, int encrypted)
{
	for (;;) {
		if (h->n >= 4) {
			size_t m = 4 + ((size_t)h->b[1] << 16 | (size_t)h->b[2] << 8 | h->b[3]);
			if (m > sizeof h->b) return 0;
			if (h->n >= m) return m;
		}
		if (x_now() > h->deadline) return 0;
		const uint8_t *d;
		size_t n;
		if (encrypted) {
			int typ;
			if (open_rec(c, &typ, &n) || typ != 22) return 0;
			d = c->rec + 5;
		} else {
			if (read_full(c->fd, c->rec, 5)) return 0;
			n = (size_t)c->rec[3] << 8 | c->rec[4];
			if (n > TLS_MAX_RECORD || read_full(c->fd, c->rec + 5, n) || c->rec[0] != 22) return 0;
			d = c->rec + 5;
		}
		if (h->n + n > sizeof h->b) return 0;
		for (size_t i = 0; i < n; i++) h->b[h->n + i] = d[i];
		h->n += n;
	}
}

static void hs_consume(hsbuf *h, size_t m)
{
	for (size_t i = m; i < h->n; i++) h->b[i - m] = h->b[i];
	h->n -= m;
}

/* leitor com limite: qualquer leitura alem do fim marca erro */
typedef struct {
	const uint8_t *b;
	size_t n, i;
	int bad;
} rd;

static const uint8_t *take(rd *r, size_t k)
{
	if (r->bad || r->n - r->i < k) {
		r->bad = 1;
		return 0;
	}
	r->i += k;
	return r->b + r->i - k;
}

static unsigned get(rd *r, int bytes)
{
	const uint8_t *p = take(r, (size_t)bytes);
	unsigned v = 0;
	for (int i = 0; p && i < bytes; i++) v = v << 8 | p[i];
	return v;
}

static int eq(const uint8_t *a, const uint8_t *b, size_t n)
{
	uint8_t d = 0;
	for (size_t i = 0; i < n; i++) d |= a[i] ^ b[i];
	return d == 0;
}

const char *tls_handshake(tls_conn *c, int fd, const char *host,
                          const uint8_t *cert, size_t cert_len,
                          const uint8_t cert_key[32], long deadline)
{
	static hsbuf hs;
	uint8_t rnd[96], pub[32], ch[512];
	size_t hl = 0, w = 0;
	while (host[hl]) hl++;
	c->fd = fd;
	c->pos = c->len = 0;
	hs.n = 0;
	hs.deadline = deadline;
	if (random_bytes(rnd, sizeof rnd)) return "sem aleatorio";
	x25519_base(pub, rnd + 64);

	/* ClientHello: mesmas extensoes e ordem do tls13.zig */
	static const uint8_t exts[] = {
		0, 43, 0, 3, 2, 3, 4,          /* supported_versions: TLS 1.3 */
		0, 13, 0, 4, 0, 2, 8, 7,       /* signature_algorithms: ed25519 */
		0, 10, 0, 4, 0, 2, 0, 0x1d,    /* supported_groups: x25519 */
		0, 45, 0, 2, 1, 1,             /* psk_key_exchange_modes: psk_dhe_ke */
		0, 51, 0, 38, 0, 36, 0, 0x1d, 0, 32, /* key_share: x25519 + chave */
	};
	size_t ext_len = sizeof exts + 32 + 4 + 5 + hl;
	size_t body = 2 + 32 + 1 + 32 + 4 + 2 + 2 + ext_len;
	if (5 + 4 + body > sizeof ch) return "nome grande demais";
#define PUT(v) (ch[w++] = (uint8_t)(v))
	PUT(22), PUT(3), PUT(1), PUT((4 + body) >> 8), PUT(4 + body);
	PUT(1), PUT(0), PUT(body >> 8), PUT(body);
	PUT(3), PUT(3);
	for (int i = 0; i < 32; i++) PUT(rnd[i]);
	PUT(32);
	for (int i = 32; i < 64; i++) PUT(rnd[i]);
	PUT(0), PUT(2), PUT(0x13), PUT(0x03), PUT(1), PUT(0); /* so CHACHA20_POLY1305; compressao nula */
	PUT(ext_len >> 8), PUT(ext_len);
	for (size_t i = 0; i < sizeof exts; i++) PUT(exts[i]);
	for (int i = 0; i < 32; i++) PUT(pub[i]);
	PUT(0), PUT(0), PUT((hl + 5) >> 8), PUT(hl + 5), PUT((hl + 3) >> 8), PUT(hl + 3), PUT(0), PUT(hl >> 8), PUT(hl);
	for (size_t i = 0; i < hl; i++) PUT(host[i]);
#undef PUT
	if (write_all(fd, ch, w)) return "escrita";

	sha256_ctx th;
	sha256_init(&th);
	sha256_update(&th, ch + 5, w - 5);

	/* ServerHello (em claro) */
	size_t m = hs_next(&hs, c, 0);
	if (!m || hs.b[0] != 2) return "sem ServerHello";
	rd r = { hs.b + 4, m - 4, 0, 0 };
	static const uint8_t hrr[32] = { 0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
	                                 0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c };
	if (get(&r, 2) != 0x0303) return "versao";
	const uint8_t *srand = take(&r, 32);
	if (srand && eq(srand, hrr, 32)) return "HelloRetryRequest";
	size_t sl = get(&r, 1);
	const uint8_t *sid = take(&r, sl);
	if (!sid || sl != 32 || !eq(sid, rnd + 32, 32)) return "session id";
	if (get(&r, 2) != 0x1303 || get(&r, 1) != 0) return "cifra";
	size_t el = get(&r, 2);
	rd e = { take(&r, el), el, 0, 0 };
	if (r.bad || !e.b) return "ServerHello truncado";
	int tls13 = 0;
	const uint8_t *spub = 0;
	while (e.i < e.n && !e.bad) {
		unsigned typ = get(&e, 2), xl = get(&e, 2);
		rd x = { take(&e, xl), xl, 0, 0 };
		if (!x.b) break;
		if (typ == 43) tls13 = get(&x, 2) == 0x0304;
		if (typ == 51 && get(&x, 2) == 0x1d && get(&x, 2) == 32) spub = take(&x, 32);
	}
	if (e.bad || !tls13 || !spub) return "ServerHello sem TLS 1.3/x25519";
	uint8_t shared[32];
	x25519(shared, rnd + 64, spub);
	wipe(rnd + 64, 32);
	uint8_t z = 0;
	for (int i = 0; i < 32; i++) z |= shared[i];
	if (!z) return "x25519";
	sha256_update(&th, hs.b, m);
	hs_consume(&hs, m);

	/* agenda de chaves (RFC 8446, 7.1) */
	uint8_t zeros[32] = {0}, empty[32], early[32], der[32], hsec[32], hh[32], chs[32], shs[32];
	sha256_ctx t0;
	sha256_init(&t0);
	sha256_final(&t0, empty);
	hmac_sha256(early, zeros, 32, zeros, 32, 0, 0);
	hkdf_label(der, early, "derived", empty, 32, 32);
	hmac_sha256(hsec, der, 32, shared, 32, 0, 0);
	wipe(shared, 32);
	sha256_final(&th, hh);
	hkdf_label(chs, hsec, "c hs traffic", hh, 32, 32);
	hkdf_label(shs, hsec, "s hs traffic", hh, 32, 32);
	set_keys(c->ckey, c->civ, c->csec, &c->cseq, chs);
	set_keys(c->skey, c->siv, c->ssec, &c->sseq, shs);

	/* EncryptedExtensions, Certificate, CertificateVerify, Finished */
	static const uint8_t order[4] = { 8, 11, 15, 20 };
	for (int k = 0; k < 4; k++) {
		m = hs_next(&hs, c, 1);
		if (!m || hs.b[0] != order[k]) return "handshake fora de ordem";
		rd b = { hs.b + 4, m - 4, 0, 0 };
		if (order[k] == 11) {
			if (get(&b, 1) != 0) return "certificado";
			size_t ll = get(&b, 3);
			rd list = { take(&b, ll), ll, 0, 0 };
			size_t cl = get(&list, 3);
			const uint8_t *got = take(&list, cl);
			if (!got || cl != cert_len || !eq(got, cert, cl)) return "certificado nao e o fixado";
		} else if (order[k] == 15) {
			if (get(&b, 2) != 0x0807 || get(&b, 2) != 64) return "assinatura nao Ed25519";
			const uint8_t *sig = take(&b, 64);
			uint8_t hash[32];
			sha256_final(&th, hash);
			/* 64 espacos + rotulo + 0 + hash (RFC 8446, 4.4.3) */
			static const char label[] = "TLS 1.3, server CertificateVerify";
			uint8_t ctx[64 + sizeof label];
			for (int i = 0; i < 64; i++) ctx[i] = ' ';
			for (size_t i = 0; i < sizeof label; i++) ctx[64 + i] = (uint8_t)label[i];
			const uint8_t *parts[2] = { ctx, hash };
			const size_t lens[2] = { sizeof ctx, 32 }; /* sizeof label inclui o 0 */
			if (!sig || ed25519_verify(cert_key, sig, parts, lens, 2)) return "CertificateVerify";
		} else if (order[k] == 20) {
			uint8_t fk[32], want[32], hash[32];
			hkdf_label(fk, shs, "finished", 0, 0, 32);
			sha256_final(&th, hash);
			hmac_sha256(want, fk, 32, hash, 32, 0, 0);
			const uint8_t *got = take(&b, 32);
			if (!got || !eq(got, want, 32)) return "Finished do servidor";
		}
		sha256_update(&th, hs.b, m);
		hs_consume(&hs, m);
	}
	if (hs.n) return "sobra no handshake";

	/* segredos de aplicacao (transcricao ate o Finished do servidor) */
	uint8_t master[32], cap[32], sap[32], fk[32], fin[4 + 32];
	sha256_final(&th, hh);
	hkdf_label(der, hsec, "derived", empty, 32, 32);
	hmac_sha256(master, der, 32, zeros, 32, 0, 0);
	hkdf_label(cap, master, "c ap traffic", hh, 32, 32);
	hkdf_label(sap, master, "s ap traffic", hh, 32, 32);

	/* ChangeCipherSpec de compatibilidade + nosso Finished */
	static const uint8_t ccs[] = { 20, 3, 3, 0, 1, 1 };
	if (write_all(fd, ccs, sizeof ccs)) return "escrita";
	hkdf_label(fk, chs, "finished", 0, 0, 32);
	fin[0] = 20, fin[1] = 0, fin[2] = 0, fin[3] = 32;
	hmac_sha256(fin + 4, fk, 32, hh, 32, 0, 0);
	if (seal(c, 22, fin, sizeof fin)) return "escrita";

	set_keys(c->ckey, c->civ, c->csec, &c->cseq, cap);
	set_keys(c->skey, c->siv, c->ssec, &c->sseq, sap);
	wipe(hsec, 32), wipe(master, 32), wipe(chs, 32), wipe(shs, 32);
	return 0;
}

int tls_write(tls_conn *c, const uint8_t *d, size_t n)
{
	do {
		size_t k = n < TLS_MAX_PLAIN ? n : TLS_MAX_PLAIN;
		if (seal(c, 23, d, k)) return -1;
		d += k;
		n -= k;
	} while (n);
	return 0;
}

/* NewSessionTicket (ignorado) e KeyUpdate, inteiros dentro do registro */
static int post_handshake(tls_conn *c, const uint8_t *d, size_t n)
{
	rd r = { d, n, 0, 0 };
	while (r.i < r.n) {
		unsigned typ = get(&r, 1);
		size_t bl = get(&r, 3);
		const uint8_t *b = take(&r, bl);
		if (!b) return -1;
		if (typ == 4) continue;
		if (typ != 24 || bl != 1) return -1;
		uint8_t s[32];
		hkdf_label(s, c->ssec, "traffic upd", 0, 0, 32);
		set_keys(c->skey, c->siv, c->ssec, &c->sseq, s);
		if (b[0] == 1) {
			static const uint8_t ku[] = { 24, 0, 0, 1, 0 };
			if (seal(c, 22, ku, sizeof ku)) return -1;
			hkdf_label(s, c->csec, "traffic upd", 0, 0, 32);
			set_keys(c->ckey, c->civ, c->csec, &c->cseq, s);
		}
	}
	return 0;
}

long tls_read(tls_conn *c, uint8_t *out, size_t n)
{
	if (c->pos == c->len) {
		int typ;
		size_t len;
		if (open_rec(c, &typ, &len)) return -1;
		if (typ == 23) {
			c->pos = 5;
			c->len = 5 + len;
		} else if (typ == 22) {
			if (post_handshake(c, c->rec + 5, len)) return -1;
			return 0;
		} else {
			return -1; /* alerta (close_notify ou erro) */
		}
	}
	size_t k = c->len - c->pos < n ? c->len - c->pos : n;
	for (size_t i = 0; i < k; i++) out[i] = c->rec[c->pos + i];
	c->pos += k;
	return (long)k;
}
