/* BLAKE2s (RFC 7693), sem chave, saida de 32 bytes. Compacto: os 10 rounds
 * e os 8 G de cada round em laco. Escolhido no lugar do BLAKE2b da
 * Monocypher: palavras de 32 bits; o BLAKE2b (64 bits) ocupava 24 KB de
 * codigo no MIPS de 32 bits. */
#ifndef NTUN_BLAKE2S_H
#define NTUN_BLAKE2S_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint32_t h[8], t[2];
	uint8_t  b[64];
	size_t   c;
} blake2s_ctx;

void blake2s_init(blake2s_ctx *x);
void blake2s_update(blake2s_ctx *x, const uint8_t *in, size_t n);
void blake2s_final(blake2s_ctx *x, uint8_t out[32]);

#endif
