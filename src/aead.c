/* ChaCha20-Poly1305; ver aead.h */
#include "aead.h"

void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;
	while (n--) *v++ = 0;
}

static uint32_t rol(uint32_t x, int n) { return x << n | x >> (32 - n); }
static uint32_t ld32(const uint8_t *p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

static void chacha_block(uint8_t out[64], const uint8_t key[32], const uint8_t nonce[12], uint32_t ctr)
{
	/* colunas e diagonais: a, b, c, d de cada quarter round */
	static const uint8_t qr[8][4] = {
		{ 0, 4, 8, 12 }, { 1, 5, 9, 13 }, { 2, 6, 10, 14 }, { 3, 7, 11, 15 },
		{ 0, 5, 10, 15 }, { 1, 6, 11, 12 }, { 2, 7, 8, 13 }, { 3, 4, 9, 14 },
	};
	uint32_t s[16], x[16];
	s[0] = 0x61707865, s[1] = 0x3320646e, s[2] = 0x79622d32, s[3] = 0x6b206574;
	for (int i = 0; i < 8; i++) s[4 + i] = ld32(key + 4 * i);
	s[12] = ctr;
	for (int i = 0; i < 3; i++) s[13 + i] = ld32(nonce + 4 * i);
	for (int i = 0; i < 16; i++) x[i] = s[i];
	for (int r = 0; r < 10; r++)
		for (int q = 0; q < 8; q++) {
			int a = qr[q][0], b = qr[q][1], c = qr[q][2], d = qr[q][3];
			x[a] += x[b]; x[d] = rol(x[d] ^ x[a], 16);
			x[c] += x[d]; x[b] = rol(x[b] ^ x[c], 12);
			x[a] += x[b]; x[d] = rol(x[d] ^ x[a], 8);
			x[c] += x[d]; x[b] = rol(x[b] ^ x[c], 7);
		}
	for (int i = 0; i < 16; i++) {
		uint32_t v = x[i] + s[i];
		for (int k = 0; k < 4; k++) out[4 * i + k] = (uint8_t)(v >> (8 * k));
	}
	wipe(s, sizeof s);
	wipe(x, sizeof x);
}

static void chacha_xor(uint8_t *out, const uint8_t *in, size_t len,
                       const uint8_t key[32], const uint8_t nonce[12])
{
	uint8_t ks[64];
	for (uint32_t ctr = 1; len; ctr++) {
		chacha_block(ks, key, nonce, ctr);
		size_t n = len < 64 ? len : 64;
		for (size_t i = 0; i < n; i++) out[i] = in[i] ^ ks[i];
		out += n;
		in += n;
		len -= n;
	}
	wipe(ks, sizeof ks);
}

/* ---- Poly1305 (TweetNaCl) */

static void add1305(uint32_t h[17], const uint32_t c[17])
{
	uint32_t u = 0;
	for (int j = 0; j < 17; j++) {
		u += h[j] + c[j];
		h[j] = u & 255;
		u >>= 8;
	}
}

typedef struct {
	uint32_t h[17], r[17];
} poly;

/* bloco de 16 bytes (os trechos do AEAD ja vem completados com zeros) */
static void poly_block(poly *p, const uint8_t m[16])
{
	uint32_t c[17], x[17];
	for (int j = 0; j < 16; j++) c[j] = m[j];
	c[16] = 1;
	add1305(p->h, c);
	for (int i = 0; i < 17; i++) {
		x[i] = 0;
		for (int j = 0; j < 17; j++)
			x[i] += p->h[j] * (j <= i ? p->r[i - j] : 320 * p->r[i + 17 - j]);
	}
	uint32_t u = 0;
	for (int j = 0; j < 16; j++) {
		u += x[j];
		p->h[j] = u & 255;
		u >>= 8;
	}
	u += x[16];
	p->h[16] = u & 3;
	u = 5 * (u >> 2);
	for (int j = 0; j < 16; j++) {
		u += p->h[j];
		p->h[j] = u & 255;
		u >>= 8;
	}
	p->h[16] += u;
}

static void poly_padded(poly *p, const uint8_t *m, size_t n)
{
	uint8_t b[16];
	while (n) {
		size_t k = n < 16 ? n : 16;
		for (size_t i = 0; i < 16; i++) b[i] = i < k ? m[i] : 0;
		poly_block(p, b);
		m += k;
		n -= k;
	}
}

static void tag(uint8_t out[16], const uint8_t key[32], const uint8_t nonce[12],
                const uint8_t *ad, size_t adl, const uint8_t *c, size_t len)
{
	static const uint32_t minusp[17] = { 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 252 };
	uint8_t pk[64], lens[16];
	poly p;
	uint32_t g[17], s[17];
	chacha_block(pk, key, nonce, 0);
	for (int j = 0; j < 17; j++) {
		p.h[j] = 0;
		p.r[j] = j < 16 ? pk[j] : 0;
	}
	p.r[3] &= 15, p.r[4] &= 252, p.r[7] &= 15, p.r[8] &= 252;
	p.r[11] &= 15, p.r[12] &= 252, p.r[15] &= 15;
	poly_padded(&p, ad, adl);
	poly_padded(&p, c, len);
	for (int i = 0; i < 8; i++) {
		lens[i] = (uint8_t)((uint64_t)adl >> (8 * i));
		lens[8 + i] = (uint8_t)((uint64_t)len >> (8 * i));
	}
	poly_block(&p, lens);
	/* h mod p: subtrai p se couber, sem desvio; depois soma s */
	for (int j = 0; j < 17; j++) g[j] = p.h[j];
	add1305(p.h, minusp);
	uint32_t m = -(p.h[16] >> 7);
	for (int j = 0; j < 17; j++) p.h[j] ^= m & (g[j] ^ p.h[j]);
	for (int j = 0; j < 17; j++) s[j] = j < 16 ? pk[16 + j] : 0;
	add1305(p.h, s);
	for (int j = 0; j < 16; j++) out[j] = (uint8_t)p.h[j];
	wipe(pk, sizeof pk);
	wipe(&p, sizeof p);
}

void aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
               const uint8_t *ad, size_t adl, const uint8_t *in, size_t len)
{
	chacha_xor(out, in, len, key, nonce);
	tag(out + len, key, nonce, ad, adl, out, len);
}

int aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
              const uint8_t *ad, size_t adl, const uint8_t *in, size_t len)
{
	uint8_t t[16];
	if (len < 16) return -1;
	len -= 16;
	tag(t, key, nonce, ad, adl, in, len);
	uint8_t d = 0;
	for (int i = 0; i < 16; i++) d |= t[i] ^ in[len + i];
	if (d) return -1;
	chacha_xor(out, in, len, key, nonce);
	return 0;
}
