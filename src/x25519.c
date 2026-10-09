/* X25519; ver x25519.h. Mesma estrutura do crypto_scalarmult do TweetNaCl
 * (escada de Montgomery com troca sem desvio: o tempo nao depende da chave). */
#include "x25519.h"

typedef int64_t gf[16];

static void car(gf o)
{
	for (int i = 0; i < 16; i++) {
		o[i] += (int64_t)1 << 16;
		int64_t c = o[i] >> 16;
		if (i < 15) o[i + 1] += c - 1;
		else o[0] += 38 * (c - 1);
		o[i] -= c * ((int64_t)1 << 16);
	}
}

/* troca p e q se b == 1, sem desvio */
static void sel(gf p, gf q, int b)
{
	int64_t c = ~((int64_t)b - 1);
	for (int i = 0; i < 16; i++) {
		int64_t t = c & (p[i] ^ q[i]);
		p[i] ^= t;
		q[i] ^= t;
	}
}

static void pack(uint8_t o[32], const gf n)
{
	gf m, t;
	for (int i = 0; i < 16; i++) t[i] = n[i];
	car(t);
	car(t);
	car(t);
	for (int j = 0; j < 2; j++) {
		m[0] = t[0] - 0xffed;
		for (int i = 1; i < 15; i++) {
			m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
			m[i - 1] &= 0xffff;
		}
		m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
		int b = (int)((m[15] >> 16) & 1);
		m[14] &= 0xffff;
		sel(t, m, 1 - b);
	}
	for (int i = 0; i < 16; i++) {
		o[2 * i] = (uint8_t)t[i];
		o[2 * i + 1] = (uint8_t)(t[i] >> 8);
	}
}

static void unpack(gf o, const uint8_t n[32])
{
	for (int i = 0; i < 16; i++) o[i] = n[2 * i] + ((int64_t)n[2 * i + 1] << 8);
	o[15] &= 0x7fff;
}

static void add(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] + b[i]; }
static void sub(gf o, const gf a, const gf b) { for (int i = 0; i < 16; i++) o[i] = a[i] - b[i]; }

/* os limbs cabem em 32 bits com sinal (|x| < 2^18 aqui): cada produto e
 * 32 x 32 -> 64 */
static void mul(gf o, const gf a, const gf b)
{
	int64_t t[31] = {0};
	for (int i = 0; i < 16; i++)
		for (int j = 0; j < 16; j++)
			t[i + j] += (int64_t)(int32_t)a[i] * (int32_t)b[j];
	for (int i = 0; i < 15; i++) t[i] += 38 * t[i + 16];
	for (int i = 0; i < 16; i++) o[i] = t[i];
	car(o);
	car(o);
}

static void inv(gf o, const gf in)
{
	gf c;
	for (int i = 0; i < 16; i++) c[i] = in[i];
	for (int a = 253; a >= 0; a--) {
		mul(c, c, c);
		if (a != 2 && a != 4) mul(c, c, in);
	}
	for (int i = 0; i < 16; i++) o[i] = c[i];
}

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32])
{
	static const gf a24 = { 0xdb41, 1 }; /* 121665 */
	uint8_t z[32];
	gf x, a, b, c, d, e, f;
	for (int i = 0; i < 31; i++) z[i] = scalar[i];
	z[31] = (scalar[31] & 127) | 64;
	z[0] &= 248;
	unpack(x, point);
	for (int i = 0; i < 16; i++) {
		b[i] = x[i];
		a[i] = c[i] = d[i] = 0;
	}
	a[0] = d[0] = 1;
	for (int i = 254; i >= 0; i--) {
		int r = (z[i >> 3] >> (i & 7)) & 1;
		sel(a, b, r);
		sel(c, d, r);
		add(e, a, c);
		sub(a, a, c);
		add(c, b, d);
		sub(b, b, d);
		mul(d, e, e);
		mul(f, a, a);
		mul(a, c, a);
		mul(c, b, e);
		add(e, a, c);
		sub(a, a, c);
		mul(b, a, a);
		sub(c, d, f);
		mul(a, c, a24);
		add(a, a, d);
		mul(c, c, a);
		mul(a, d, f);
		mul(d, b, x);
		mul(b, e, e);
		sel(a, b, r);
		sel(c, d, r);
	}
	inv(c, c);
	mul(a, a, c);
	pack(out, a);
	for (int i = 0; i < 32; i++) z[i] = 0;
}

void x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
	static const uint8_t nine[32] = { 9 };
	x25519(out, scalar, nine);
}
