/* BLAKE2s; ver blake2s.h. Segue a referencia do RFC 7693, apendice C. */
#include "blake2s.h"

static const uint32_t iv[8] = {
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

static const uint8_t sigma[10][16] = {
	{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 },
	{ 14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3 },
	{ 11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4 },
	{ 7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8 },
	{ 9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13 },
	{ 2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9 },
	{ 12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11 },
	{ 13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10 },
	{ 6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5 },
	{ 10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0 },
};

/* colunas e diagonais: a, b, c, d de cada G */
static const uint8_t gi[8][4] = {
	{ 0, 4, 8, 12 }, { 1, 5, 9, 13 }, { 2, 6, 10, 14 }, { 3, 7, 11, 15 },
	{ 0, 5, 10, 15 }, { 1, 6, 11, 12 }, { 2, 7, 8, 13 }, { 3, 4, 9, 14 },
};

static uint32_t ror(uint32_t x, int n) { return x >> n | x << (32 - n); }

static void compress(blake2s_ctx *x, int last)
{
	uint32_t v[16], m[16];
	for (int i = 0; i < 8; i++) {
		v[i] = x->h[i];
		v[i + 8] = iv[i];
	}
	v[12] ^= x->t[0];
	v[13] ^= x->t[1];
	if (last) v[14] = ~v[14];
	for (int i = 0; i < 16; i++)
		m[i] = (uint32_t)x->b[4 * i] | (uint32_t)x->b[4 * i + 1] << 8 |
		       (uint32_t)x->b[4 * i + 2] << 16 | (uint32_t)x->b[4 * i + 3] << 24;
	for (int r = 0; r < 10; r++) {
		for (int g = 0; g < 8; g++) {
			int a = gi[g][0], b = gi[g][1], c = gi[g][2], d = gi[g][3];
			v[a] += v[b] + m[sigma[r][2 * g]];
			v[d] = ror(v[d] ^ v[a], 16);
			v[c] += v[d];
			v[b] = ror(v[b] ^ v[c], 12);
			v[a] += v[b] + m[sigma[r][2 * g + 1]];
			v[d] = ror(v[d] ^ v[a], 8);
			v[c] += v[d];
			v[b] = ror(v[b] ^ v[c], 7);
		}
	}
	for (int i = 0; i < 8; i++) x->h[i] ^= v[i] ^ v[i + 8];
}

void blake2s_init(blake2s_ctx *x)
{
	for (int i = 0; i < 8; i++) x->h[i] = iv[i];
	x->h[0] ^= 0x01010000 ^ 32; /* sem chave, saida de 32 bytes */
	x->t[0] = x->t[1] = 0;
	x->c = 0;
}

void blake2s_update(blake2s_ctx *x, const uint8_t *in, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (x->c == 64) { /* bloco cheio e ha mais: comprime (nao e o ultimo) */
			x->t[0] += 64;
			if (x->t[0] < 64) x->t[1]++;
			compress(x, 0);
			x->c = 0;
		}
		x->b[x->c++] = in[i];
	}
}

void blake2s_final(blake2s_ctx *x, uint8_t out[32])
{
	x->t[0] += (uint32_t)x->c;
	if (x->t[0] < x->c) x->t[1]++;
	while (x->c < 64) x->b[x->c++] = 0;
	compress(x, 1);
	for (int i = 0; i < 32; i++) out[i] = (uint8_t)(x->h[i / 4] >> (8 * (i % 4)));
}
