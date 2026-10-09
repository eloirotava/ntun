/* X25519 (RFC 7748) compacto, no estilo do TweetNaCl: corpo com 16 limbs
 * de 16 bits, lacos simples, sem tabelas. Lento, mas e um handshake por
 * conexao; no MIPS cada produto e um so mult (32 x 32 -> 64 bits). */
#ifndef NTUN_X25519_H
#define NTUN_X25519_H

#include <stdint.h>

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);

#endif
