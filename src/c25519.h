/* X25519 (RFC 7748) e verificacao Ed25519 (RFC 8032) compactos, no estilo
 * do TweetNaCl: corpo com 16 limbs de 16 bits, lacos simples, sem tabelas.
 * Lento, mas e um handshake por conexao; no MIPS cada produto e um so mult
 * (32 x 32 -> 64 bits). Quem nao usa a verificacao nao leva o codigo dela
 * (secoes por funcao + --gc-sections). */
#ifndef NTUN_X25519_H
#define NTUN_X25519_H

#include <stddef.h>
#include <stdint.h>

void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);
void x25519_base(uint8_t out[32], const uint8_t scalar[32]);

/* assinatura Ed25519 de msg (em n partes) pela chave pk: 0 ou -1 */
int ed25519_verify(const uint8_t pk[32], const uint8_t sig[64],
                   const uint8_t *const *msg, const size_t *len, int n);

#endif
