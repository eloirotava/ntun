/* SHA-256 e SHA-512 (FIPS 180-4) compactos (rounds em laco), HMAC-SHA256 e
 * o HKDF-Expand-Label do TLS 1.3. O SHA-512 so serve a verificacao Ed25519. */
#ifndef NTUN_SHA2_H
#define NTUN_SHA2_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint32_t s[8];
	uint64_t len;
	uint8_t  b[64];
	size_t   n;
} sha256_ctx;

typedef struct {
	uint64_t s[8];
	uint64_t len;
	uint8_t  b[128];
	size_t   n;
} sha512_ctx;

void sha256_init(sha256_ctx *x);
void sha256_update(sha256_ctx *x, const void *in, size_t n);
void sha256_final(sha256_ctx *x, uint8_t out[32]); /* nao altera x: serve de "peek" */
void sha512_init(sha512_ctx *x);
void sha512_update(sha512_ctx *x, const void *in, size_t n);
void sha512_final(sha512_ctx *x, uint8_t out[64]);

/* HMAC-SHA256(key, a || b) */
void hmac_sha256(uint8_t out[32], const uint8_t *key, size_t kl,
                 const uint8_t *a, size_t al, const uint8_t *b, size_t bl);
/* HKDF-Expand-Label(secret, "tls13 " + label, ctx, len), len <= 32 */
void hkdf_label(uint8_t *out, const uint8_t secret[32], const char *label,
                const uint8_t *ctx, size_t cl, size_t len);

#endif
