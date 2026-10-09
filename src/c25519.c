/* X25519; ver x25519.h. Mesma estrutura do crypto_scalarmult do TweetNaCl
 * (escada de Montgomery com troca sem desvio: o tempo nao depende da chave). */
#include "c25519.h"
#include "sha2.h"

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

/* ---------------------------------------------------------------- Ed25519 */

/* constantes da curva (do TweetNaCl), guardadas como u16: como int64 seriam
 * 3/4 zeros */
static const uint16_t kD[16] = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 };
static const uint16_t kD2[16] = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 };
static const uint16_t kX[16] = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 };
static const uint16_t kY[16] = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 };
static const uint16_t kI[16] = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };
static const uint8_t L[32] = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
                               0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };

static void gfc(gf o, const uint16_t c[16]) { for (int i = 0; i < 16; i++) o[i] = c[i]; }
static void gfn(gf o, int64_t v) { for (int i = 0; i < 16; i++) o[i] = i ? 0 : v; }
static void gcopy(gf o, const gf a) { for (int i = 0; i < 16; i++) o[i] = a[i]; }

static int neq(const gf a, const gf b)
{
	uint8_t c[32], d[32], z = 0;
	pack(c, a);
	pack(d, b);
	for (int i = 0; i < 32; i++) z |= c[i] ^ d[i];
	return z != 0;
}

static int par(const gf a)
{
	uint8_t d[32];
	pack(d, a);
	return d[0] & 1;
}

static void pow2523(gf o, const gf in)
{
	gf c;
	gcopy(c, in);
	for (int a = 250; a >= 0; a--) {
		mul(c, c, c);
		if (a != 1) mul(c, c, in);
	}
	gcopy(o, c);
}

typedef int64_t pt[4][16];

static void padd(pt p, pt q)
{
	gf a, b, c, d, t, e, f, g, h, d2;
	sub(a, p[1], p[0]);
	sub(t, q[1], q[0]);
	mul(a, a, t);
	add(b, p[0], p[1]);
	add(t, q[0], q[1]);
	mul(b, b, t);
	mul(c, p[3], q[3]);
	gfc(d2, kD2);
	mul(c, c, d2);
	mul(d, p[2], q[2]);
	add(d, d, d);
	sub(e, b, a);
	sub(f, d, c);
	add(g, d, c);
	add(h, b, a);
	mul(p[0], e, f);
	mul(p[1], h, g);
	mul(p[2], g, f);
	mul(p[3], e, h);
}

static void cswap(pt p, pt q, int b)
{
	for (int i = 0; i < 4; i++) sel(p[i], q[i], b);
}

static void ppack(uint8_t r[32], pt p)
{
	gf tx, ty, zi;
	inv(zi, p[2]);
	mul(tx, p[0], zi);
	mul(ty, p[1], zi);
	pack(r, ty);
	r[31] ^= (uint8_t)(par(tx) << 7);
}

/* p = [s]q (escada com troca sem desvio, como no TweetNaCl) */
static void pmul(pt p, pt q, const uint8_t s[32])
{
	gfn(p[0], 0);
	gfn(p[1], 1);
	gfn(p[2], 1);
	gfn(p[3], 0);
	for (int i = 255; i >= 0; i--) {
		int b = (s[i / 8] >> (i & 7)) & 1;
		cswap(p, q, b);
		padd(q, p);
		padd(p, p);
		cswap(p, q, b);
	}
}

/* -A a partir da chave publica; -1 se nao for ponto da curva */
static int unpackneg(pt r, const uint8_t p[32])
{
	gf t, chk, num, den, den2, den4, den6, d;
	gfn(r[2], 1);
	unpack(r[1], p);
	mul(num, r[1], r[1]);
	gfc(d, kD);
	mul(den, num, d);
	sub(num, num, r[2]);
	add(den, r[2], den);
	mul(den2, den, den);
	mul(den4, den2, den2);
	mul(den6, den4, den2);
	mul(t, den6, num);
	mul(t, t, den);
	pow2523(t, t);
	mul(t, t, num);
	mul(t, t, den);
	mul(t, t, den);
	mul(r[0], t, den);
	mul(chk, r[0], r[0]);
	mul(chk, chk, den);
	if (neq(chk, num)) {
		gf i;
		gfc(i, kI);
		mul(r[0], r[0], i);
	}
	mul(chk, r[0], r[0]);
	mul(chk, chk, den);
	if (neq(chk, num)) return -1;
	if (par(r[0]) == (p[31] >> 7)) {
		gf z;
		gfn(z, 0);
		sub(r[0], z, r[0]);
	}
	mul(r[3], r[0], r[1]);
	return 0;
}

/* h (64 bytes) mod L */
static void reduce(uint8_t r[32], const uint8_t h[64])
{
	int64_t x[64], carry;
	for (int i = 0; i < 64; i++) x[i] = h[i];
	for (int i = 63; i >= 32; i--) {
		int j;
		carry = 0;
		for (j = i - 32; j < i - 12; j++) {
			x[j] += carry - 16 * x[i] * L[j - (i - 32)];
			carry = (x[j] + 128) >> 8;
			x[j] -= carry * 256;
		}
		x[j] += carry;
		x[i] = 0;
	}
	carry = 0;
	for (int j = 0; j < 32; j++) {
		x[j] += carry - (x[31] >> 4) * L[j];
		carry = x[j] >> 8;
		x[j] &= 255;
	}
	for (int j = 0; j < 32; j++) x[j] -= carry * L[j];
	for (int i = 0; i < 32; i++) {
		x[i + 1] += x[i] >> 8;
		r[i] = (uint8_t)(x[i] & 255);
	}
}

/* s < L (assinatura canonica) */
static int canonical(const uint8_t s[32])
{
	for (int k = 31; k >= 0; k--) {
		if (s[k] < L[k]) return 1;
		if (s[k] > L[k]) return 0;
	}
	return 0;
}

int ed25519_verify(const uint8_t pk[32], const uint8_t sig[64],
                   const uint8_t *const *msg, const size_t *len, int n)
{
	pt p, q;
	uint8_t h[64], hr[32], t[32];
	if (!canonical(sig + 32) || unpackneg(q, pk)) return -1;
	sha512_ctx x;
	sha512_init(&x);
	sha512_update(&x, sig, 32);
	sha512_update(&x, pk, 32);
	for (int i = 0; i < n; i++) sha512_update(&x, msg[i], len[i]);
	sha512_final(&x, h);
	reduce(hr, h);
	/* [s]B - [h]A, empacotado, tem que dar R */
	pmul(p, q, hr);
	gfc(q[0], kX);
	gfc(q[1], kY);
	gfn(q[2], 1);
	mul(q[3], q[0], q[1]);
	pt sb;
	pmul(sb, q, sig + 32);
	padd(p, sb);
	ppack(t, p);
	uint8_t d = 0;
	for (int i = 0; i < 32; i++) d |= t[i] ^ sig[i];
	return d ? -1 : 0;
}
