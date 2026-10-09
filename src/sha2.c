/* SHA-256, SHA-512, HMAC e HKDF; ver sha2.h */
#include "sha2.h"

static const uint32_t k256[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static const uint64_t k512[80] = {
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
	0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
	0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
	0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
	0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
	0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
	0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
	0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
	0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
	0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
	0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
	0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
	0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
	0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
	0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
	0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
	0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
};

/* ---------------------------------------------------------------- 256 */

static uint32_t ror32(uint32_t x, int n) { return x >> n | x << (32 - n); }

static void block256(uint32_t s[8], const uint8_t *b)
{
	uint32_t w[64], v[8];
	for (int i = 0; i < 16; i++)
		w[i] = (uint32_t)b[4 * i] << 24 | (uint32_t)b[4 * i + 1] << 16 | (uint32_t)b[4 * i + 2] << 8 | b[4 * i + 3];
	for (int i = 16; i < 64; i++) {
		uint32_t x = w[i - 15], y = w[i - 2];
		w[i] = w[i - 16] + w[i - 7] + (ror32(x, 7) ^ ror32(x, 18) ^ x >> 3) + (ror32(y, 17) ^ ror32(y, 19) ^ y >> 10);
	}
	for (int i = 0; i < 8; i++) v[i] = s[i];
	for (int i = 0; i < 64; i++) {
		uint32_t e = v[4], a = v[0];
		uint32_t t1 = v[7] + (ror32(e, 6) ^ ror32(e, 11) ^ ror32(e, 25)) + ((e & v[5]) ^ (~e & v[6])) + k256[i] + w[i];
		uint32_t t2 = (ror32(a, 2) ^ ror32(a, 13) ^ ror32(a, 22)) + ((a & v[1]) ^ (a & v[2]) ^ (v[1] & v[2]));
		for (int j = 7; j > 0; j--) v[j] = v[j - 1];
		v[4] += t1;
		v[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++) s[i] += v[i];
}

void sha256_init(sha256_ctx *x)
{
	static const uint32_t iv[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	                                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
	for (int i = 0; i < 8; i++) x->s[i] = iv[i];
	x->len = 0;
	x->n = 0;
}

void sha256_update(sha256_ctx *x, const void *in, size_t n)
{
	const uint8_t *p = in;
	x->len += n;
	while (n--) {
		x->b[x->n++] = *p++;
		if (x->n == 64) {
			block256(x->s, x->b);
			x->n = 0;
		}
	}
}

void sha256_final(sha256_ctx *x, uint8_t out[32])
{
	sha256_ctx c = *x; /* copia: o original segue utilizavel */
	uint64_t bits = c.len * 8;
	uint8_t pad = 0x80;
	sha256_update(&c, &pad, 1);
	pad = 0;
	while (c.n != 56) sha256_update(&c, &pad, 1);
	for (int i = 7; i >= 0; i--) {
		uint8_t b = (uint8_t)(bits >> (8 * i));
		sha256_update(&c, &b, 1);
	}
	for (int i = 0; i < 32; i++) out[i] = (uint8_t)(c.s[i / 4] >> (24 - 8 * (i % 4)));
}

/* ---------------------------------------------------------------- 512 */

static uint64_t ror64(uint64_t x, int n) { return x >> n | x << (64 - n); }

static void block512(uint64_t s[8], const uint8_t *b)
{
	uint64_t w[80], v[8];
	for (int i = 0; i < 16; i++) {
		w[i] = 0;
		for (int k = 0; k < 8; k++) w[i] = w[i] << 8 | b[8 * i + k];
	}
	for (int i = 16; i < 80; i++) {
		uint64_t x = w[i - 15], y = w[i - 2];
		w[i] = w[i - 16] + w[i - 7] + (ror64(x, 1) ^ ror64(x, 8) ^ x >> 7) + (ror64(y, 19) ^ ror64(y, 61) ^ y >> 6);
	}
	for (int i = 0; i < 8; i++) v[i] = s[i];
	for (int i = 0; i < 80; i++) {
		uint64_t e = v[4], a = v[0];
		uint64_t t1 = v[7] + (ror64(e, 14) ^ ror64(e, 18) ^ ror64(e, 41)) + ((e & v[5]) ^ (~e & v[6])) + k512[i] + w[i];
		uint64_t t2 = (ror64(a, 28) ^ ror64(a, 34) ^ ror64(a, 39)) + ((a & v[1]) ^ (a & v[2]) ^ (v[1] & v[2]));
		for (int j = 7; j > 0; j--) v[j] = v[j - 1];
		v[4] += t1;
		v[0] = t1 + t2;
	}
	for (int i = 0; i < 8; i++) s[i] += v[i];
}

void sha512_init(sha512_ctx *x)
{
	static const uint64_t iv[8] = { 0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	                                0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179 };
	for (int i = 0; i < 8; i++) x->s[i] = iv[i];
	x->len = 0;
	x->n = 0;
}

void sha512_update(sha512_ctx *x, const void *in, size_t n)
{
	const uint8_t *p = in;
	x->len += n;
	while (n--) {
		x->b[x->n++] = *p++;
		if (x->n == 128) {
			block512(x->s, x->b);
			x->n = 0;
		}
	}
}

void sha512_final(sha512_ctx *x, uint8_t out[64])
{
	uint64_t bits = x->len * 8;
	uint8_t pad = 0x80;
	sha512_update(x, &pad, 1);
	pad = 0;
	while (x->n != 120) sha512_update(x, &pad, 1); /* + 8 zeros do tamanho de 128 bits */
	for (int i = 7; i >= 0; i--) {
		uint8_t b = (uint8_t)(bits >> (8 * i));
		sha512_update(x, &b, 1);
	}
	for (int i = 0; i < 64; i++) out[i] = (uint8_t)(x->s[i / 8] >> (56 - 8 * (i % 8)));
}

/* ------------------------------------------------------------ HMAC/HKDF */

void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t kl,
                 const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
	uint8_t k[64] = {0}, pad[64], inner[32];
	sha256_ctx x;
	if (kl > 64) {
		sha256_init(&x);
		sha256_update(&x, key, kl);
		sha256_final(&x, k);
	} else {
		for (size_t i = 0; i < kl; i++) k[i] = key[i];
	}
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x36;
	sha256_init(&x);
	sha256_update(&x, pad, 64);
	sha256_update(&x, a, al);
	sha256_update(&x, b, bl);
	sha256_final(&x, inner);
	for (int i = 0; i < 64; i++) pad[i] = k[i] ^ 0x5c;
	sha256_init(&x);
	sha256_update(&x, pad, 64);
	sha256_update(&x, inner, 32);
	sha256_final(&x, out);
}

void hkdf_label(uint8_t *out, const uint8_t secret[32], const char *label,
                const uint8_t *ctx, size_t cl, size_t len)
{
	uint8_t info[2 + 1 + 6 + 32 + 1 + 32 + 1], t[32];
	size_t n = 0, ll = 0;
	while (label[ll]) ll++;
	info[n++] = 0;
	info[n++] = (uint8_t)len;
	info[n++] = (uint8_t)(6 + ll);
	for (const char *p = "tls13 "; *p; p++) info[n++] = (uint8_t)*p;
	for (size_t i = 0; i < ll; i++) info[n++] = (uint8_t)label[i];
	info[n++] = (uint8_t)cl;
	for (size_t i = 0; i < cl; i++) info[n++] = ctx[i];
	info[n++] = 1;
	hmac_sha256(t, secret, 32, info, n, 0, 0);
	for (size_t i = 0; i < len; i++) out[i] = t[i];
}
