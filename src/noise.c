/* Noise_IK_25519_ChaChaPoly_BLAKE2b; ver noise.h. Os nomes seguem o
 * documento do Noise (secao 5: CipherState, SymmetricState, HandshakeState). */
#include "noise.h"
#include "../vendor/monocypher.h"

#define HASHLEN  64
#define BLOCKLEN 128

static const char protocol_name[] = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

static void copy(uint8_t *d, const uint8_t *s, size_t n) { while (n--) *d++ = *s++; }

void noise_wipe(void *p, size_t n) { crypto_wipe(p, n); }

void noise_public_key(uint8_t pub[32], const uint8_t priv[32])
{
	crypto_x25519_public_key(pub, priv);
}

static void hash2(uint8_t out[HASHLEN], const uint8_t *a, size_t al, const uint8_t *b, size_t bl)
{
	crypto_blake2b_ctx x;
	crypto_blake2b_init(&x, HASHLEN);
	crypto_blake2b_update(&x, a, al);
	crypto_blake2b_update(&x, b, bl);
	crypto_blake2b_final(&x, out);
}

/* HMAC-BLAKE2b (RFC 2104); chave sempre de HASHLEN bytes aqui */
static void hmac(uint8_t out[HASHLEN], const uint8_t key[HASHLEN],
                 const uint8_t *d1, size_t l1, const uint8_t *d2, size_t l2)
{
	uint8_t pad[BLOCKLEN], inner[HASHLEN];
	crypto_blake2b_ctx x;
	for (int i = 0; i < BLOCKLEN; i++) pad[i] = (i < HASHLEN ? key[i] : 0) ^ 0x36;
	crypto_blake2b_init(&x, HASHLEN);
	crypto_blake2b_update(&x, pad, BLOCKLEN);
	crypto_blake2b_update(&x, d1, l1);
	crypto_blake2b_update(&x, d2, l2);
	crypto_blake2b_final(&x, inner);
	for (int i = 0; i < BLOCKLEN; i++) pad[i] ^= 0x36 ^ 0x5c;
	hash2(out, pad, BLOCKLEN, inner, HASHLEN);
	crypto_wipe(pad, sizeof pad);
	crypto_wipe(inner, sizeof inner);
}

/* HKDF com 2 saidas */
static void hkdf(const uint8_t ck[HASHLEN], const uint8_t *ikm, size_t ikm_len,
                 uint8_t o1[HASHLEN], uint8_t o2[HASHLEN])
{
	static const uint8_t one = 1, two = 2;
	uint8_t t[HASHLEN];
	hmac(t, ck, ikm, ikm_len, 0, 0);
	hmac(o1, t, &one, 1, 0, 0);
	hmac(o2, t, o1, HASHLEN, &two, 1);
	crypto_wipe(t, sizeof t);
}

/* nonce do ChaChaPoly no Noise: 4 bytes zero + contador de 64 bits LE */
static void aead_ctx(crypto_aead_ctx *x, const noise_cipher *c)
{
	uint8_t n[12] = {0};
	for (int i = 0; i < 8; i++) n[4 + i] = (uint8_t)(c->n >> (8 * i));
	crypto_aead_init_ietf(x, c->k, n);
}

static size_t encrypt_ad(noise_cipher *c, const uint8_t *ad, size_t adl,
                         const uint8_t *in, size_t len, uint8_t *out)
{
	crypto_aead_ctx x;
	aead_ctx(&x, c); /* contexto novo por mensagem: o write troca a chave */
	crypto_aead_write(&x, out, out + len, ad, adl, in, len);
	crypto_wipe(&x, sizeof x);
	c->n++;
	return len + NOISE_TAG;
}

static long decrypt_ad(noise_cipher *c, const uint8_t *ad, size_t adl,
                       const uint8_t *in, size_t len, uint8_t *out)
{
	crypto_aead_ctx x;
	if (len < NOISE_TAG) return -1;
	len -= NOISE_TAG;
	aead_ctx(&x, c);
	int bad = crypto_aead_read(&x, out, in + len, ad, adl, in, len);
	crypto_wipe(&x, sizeof x);
	if (bad) return -1;
	c->n++;
	return (long)len;
}

size_t noise_encrypt(noise_cipher *c, const uint8_t *in, size_t len, uint8_t *out)
{
	return encrypt_ad(c, 0, 0, in, len, out);
}

long noise_decrypt(noise_cipher *c, const uint8_t *in, size_t len, uint8_t *out)
{
	return decrypt_ad(c, 0, 0, in, len, out);
}

static void mix_hash(noise_hs *hs, const uint8_t *d, size_t l)
{
	hash2(hs->h, hs->h, HASHLEN, d, l);
}

/* DH + MixKey; recusa resultado zero (ponto de ordem pequena) */
static int mix_dh(noise_hs *hs, const uint8_t priv[32], const uint8_t pub[32])
{
	uint8_t dh[32], o1[HASHLEN], o2[HASHLEN];
	uint8_t z = 0;
	crypto_x25519(dh, priv, pub);
	for (int i = 0; i < 32; i++) z |= dh[i];
	hkdf(hs->ck, dh, 32, o1, o2);
	copy(hs->ck, o1, HASHLEN);
	copy(hs->c.k, o2, 32);
	hs->c.n = 0;
	hs->c.has_k = 1;
	crypto_wipe(dh, sizeof dh);
	crypto_wipe(o1, sizeof o1);
	crypto_wipe(o2, sizeof o2);
	return z ? 0 : -1;
}

/* EncryptAndHash / DecryptAndHash (sempre com chave, no IK) */
static size_t enc_hash(noise_hs *hs, const uint8_t *in, size_t len, uint8_t *out)
{
	size_t n = encrypt_ad(&hs->c, hs->h, HASHLEN, in, len, out);
	mix_hash(hs, out, n);
	return n;
}

static long dec_hash(noise_hs *hs, const uint8_t *in, size_t len, uint8_t *out)
{
	long n = decrypt_ad(&hs->c, hs->h, HASHLEN, in, len, out);
	if (n >= 0) mix_hash(hs, in, len);
	return n;
}

static void split(noise_hs *hs, noise_cipher *c1, noise_cipher *c2)
{
	uint8_t o1[HASHLEN], o2[HASHLEN];
	hkdf(hs->ck, 0, 0, o1, o2);
	copy(c1->k, o1, 32);
	copy(c2->k, o2, 32);
	c1->n = c2->n = 0;
	c1->has_k = c2->has_k = 1;
	crypto_wipe(o1, sizeof o1);
	crypto_wipe(o2, sizeof o2);
	/* o estado do handshake (chaves efemeras) quem limpa e o chamador,
	 * depois de usar hs->h se quiser (noise_wipe(hs, sizeof *hs)) */
}

void noise_ik_init(noise_hs *hs, int initiator, const uint8_t s_priv[32],
                   const uint8_t *rs, const uint8_t *prologue, size_t prologue_len)
{
	uint8_t *p = (uint8_t *)hs;
	for (size_t i = 0; i < sizeof *hs; i++) p[i] = 0;
	/* nome < HASHLEN: h = nome completado com zeros */
	copy(hs->h, (const uint8_t *)protocol_name, sizeof protocol_name - 1);
	copy(hs->ck, hs->h, HASHLEN);
	mix_hash(hs, prologue, prologue_len);
	copy(hs->s_priv, s_priv, 32);
	crypto_x25519_public_key(hs->s_pub, s_priv);
	/* pre-mensagem "<- s": a estatica do respondedor */
	if (initiator) {
		copy(hs->rs, rs, 32);
		mix_hash(hs, hs->rs, 32);
	} else {
		mix_hash(hs, hs->s_pub, 32);
	}
}

long noise_ik_write1(noise_hs *hs, const uint8_t e_priv[32],
                     const uint8_t *payload, size_t len, uint8_t *out)
{
	size_t o = 32;
	copy(hs->e_priv, e_priv, 32);
	crypto_x25519_public_key(hs->e_pub, e_priv);
	copy(out, hs->e_pub, 32);                       /* e */
	mix_hash(hs, hs->e_pub, 32);
	if (mix_dh(hs, hs->e_priv, hs->rs)) return -1;  /* es */
	o += enc_hash(hs, hs->s_pub, 32, out + o);      /* s */
	if (mix_dh(hs, hs->s_priv, hs->rs)) return -1;  /* ss */
	o += enc_hash(hs, payload, len, out + o);
	return (long)o;
}

long noise_ik_read1(noise_hs *hs, const uint8_t *msg, size_t len, uint8_t *payload_out)
{
	if (len < NOISE_MSG1_LEN(0)) return -1;
	copy(hs->re, msg, 32);                          /* e */
	mix_hash(hs, hs->re, 32);
	if (mix_dh(hs, hs->s_priv, hs->re)) return -1;  /* es */
	if (dec_hash(hs, msg + 32, 48, hs->rs) < 0) return -1; /* s */
	if (mix_dh(hs, hs->s_priv, hs->rs)) return -1;  /* ss */
	return dec_hash(hs, msg + 80, len - 80, payload_out);
}

long noise_ik_write2(noise_hs *hs, const uint8_t e_priv[32],
                     const uint8_t *payload, size_t len, uint8_t *out,
                     noise_cipher *send, noise_cipher *recv)
{
	size_t o = 32;
	copy(hs->e_priv, e_priv, 32);
	crypto_x25519_public_key(hs->e_pub, e_priv);
	copy(out, hs->e_pub, 32);                       /* e */
	mix_hash(hs, hs->e_pub, 32);
	if (mix_dh(hs, hs->e_priv, hs->re)) return -1;  /* ee */
	if (mix_dh(hs, hs->e_priv, hs->rs)) return -1;  /* se */
	o += enc_hash(hs, payload, len, out + o);
	split(hs, recv, send); /* c1: iniciador -> respondedor */
	return (long)o;
}

long noise_ik_read2(noise_hs *hs, const uint8_t *msg, size_t len, uint8_t *payload_out,
                    noise_cipher *send, noise_cipher *recv)
{
	if (len < NOISE_MSG2_LEN(0)) return -1;
	copy(hs->re, msg, 32);                          /* e */
	mix_hash(hs, hs->re, 32);
	if (mix_dh(hs, hs->e_priv, hs->re)) return -1;  /* ee */
	if (mix_dh(hs, hs->s_priv, hs->re)) return -1;  /* se */
	long n = dec_hash(hs, msg + 32, len - 32, payload_out);
	if (n < 0) return -1;
	split(hs, send, recv);
	return n;
}
