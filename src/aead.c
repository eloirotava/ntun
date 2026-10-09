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

/* ---- Poly1305 com 5 limbs de 26 bits (como o poly1305-donna de 32 bits):
 * 25 produtos 32 x 32 -> 64 por bloco (um multu cada no MIPS), contra 289
 * da versao com limbs de 8 bits. */

typedef struct {
	uint32_t r[5], s[4], h[5];
} poly;

static void poly_init(poly *p, const uint8_t key[16])
{
	p->r[0] = ld32(key + 0) & 0x3ffffff;
	p->r[1] = (ld32(key + 3) >> 2) & 0x3ffff03;
	p->r[2] = (ld32(key + 6) >> 4) & 0x3ffc0ff;
	p->r[3] = (ld32(key + 9) >> 6) & 0x3f03fff;
	p->r[4] = (ld32(key + 12) >> 8) & 0x00fffff;
	for (int i = 0; i < 4; i++) p->s[i] = p->r[i + 1] * 5;
	for (int i = 0; i < 5; i++) p->h[i] = 0;
}

/* bloco de 16 bytes (os trechos do AEAD ja vem completados com zeros) */
static void poly_block(poly *p, const uint8_t m[16])
{
	const uint32_t *r = p->r, *s = p->s;
	uint32_t *h = p->h;
	h[0] += ld32(m + 0) & 0x3ffffff;
	h[1] += (ld32(m + 3) >> 2) & 0x3ffffff;
	h[2] += (ld32(m + 6) >> 4) & 0x3ffffff;
	h[3] += (ld32(m + 9) >> 6) & 0x3ffffff;
	h[4] += (ld32(m + 12) >> 8) | (1 << 24);
	/* d[i] = soma de h[j] * r[i-j], com r[k] (k < 0) dobrado em 5 * r[k+5] */
	uint64_t d[5];
	for (int i = 0; i < 5; i++) {
		d[i] = 0;
		for (int j = 0; j < 5; j++)
			d[i] += (uint64_t)h[j] * (j <= i ? r[i - j] : s[i - j + 4]);
	}
	uint32_t c = 0;
	for (int i = 0; i < 5; i++) {
		d[i] += c;
		c = (uint32_t)(d[i] >> 26);
		h[i] = (uint32_t)d[i] & 0x3ffffff;
	}
	h[0] += c * 5;
	h[1] += h[0] >> 26;
	h[0] &= 0x3ffffff;
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
	uint8_t pk[64], lens[16];
	poly p;
	chacha_block(pk, key, nonce, 0);
	poly_init(&p, pk);
	poly_padded(&p, ad, adl);
	poly_padded(&p, c, len);
	for (int i = 0; i < 8; i++) {
		lens[i] = (uint8_t)((uint64_t)adl >> (8 * i));
		lens[8 + i] = (uint8_t)((uint64_t)len >> (8 * i));
	}
	poly_block(&p, lens);

	/* carrega tudo, e h mod p: subtrai p se couber, sem desvio */
	uint32_t *h = p.h, g[5], cy = 0;
	for (int i = 1; i < 5; i++) {
		h[i] += cy;
		cy = h[i] >> 26;
		h[i] &= 0x3ffffff;
	}
	h[0] += cy * 5;
	cy = h[0] >> 26;
	h[0] &= 0x3ffffff;
	h[1] += cy;
	cy = 5;
	for (int i = 0; i < 5; i++) {
		g[i] = h[i] + cy;
		cy = g[i] >> 26;
		g[i] &= 0x3ffffff;
	}
	g[4] = g[4] + (cy << 26) - (1 << 26); /* h + 5 - 2^130 */
	uint32_t m = (g[4] >> 31) - 1;       /* tudo 1 se h >= p */
	for (int i = 0; i < 5; i++) h[i] = (h[i] & ~m) | (g[i] & m);

	/* h (130 bits em 26) -> 128 bits em 32, + s */
	uint32_t w[4] = {
		h[0] | h[1] << 26,
		h[1] >> 6 | h[2] << 20,
		h[2] >> 12 | h[3] << 14,
		h[3] >> 18 | h[4] << 8,
	};
	uint64_t f = 0;
	for (int i = 0; i < 4; i++) {
		f += (uint64_t)w[i] + ld32(pk + 16 + 4 * i);
		for (int k = 0; k < 4; k++) out[4 * i + k] = (uint8_t)(f >> (8 * k));
		f >>= 32;
	}
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
