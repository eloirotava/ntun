/* Noise_IK_25519_ChaChaPoly_BLAKE2s (noiseprotocol.org, rev 34), com
 * criptografia compacta propria (x25519.c, aead.c, blake2s.c; conferida
 * contra a Monocypher e os vetores oficiais nos testes). So o
 * necessario para o ntun: o iniciador (roteador) conhece a chave estatica do
 * respondedor (VPS) e se identifica com a sua.
 *
 *   <- s
 *   ...
 *   -> e, es, s, ss
 *   <- e, ee, se
 */
#ifndef NTUN_NOISE_H
#define NTUN_NOISE_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
	uint8_t  k[32];
	uint64_t n;
	int      has_k;
} noise_cipher;

typedef struct {
	noise_cipher c;
	uint8_t ck[32];
	uint8_t h[32];
	uint8_t s_priv[32], s_pub[32];
	uint8_t e_priv[32], e_pub[32];
	uint8_t rs[32], re[32];
} noise_hs;

/* tamanho das mensagens de handshake (payload incluso) */
#define NOISE_MSG1_LEN(payload) (32 + 48 + (payload) + 16)
#define NOISE_MSG2_LEN(payload) (32 + (payload) + 16)
#define NOISE_TAG 16

/* rs: chave publica do respondedor (iniciador) ou NULL (respondedor) */
void noise_ik_init(noise_hs *hs, int initiator, const uint8_t s_priv[32],
                   const uint8_t *rs, const uint8_t *prologue, size_t prologue_len);

/* iniciador: escreve a 1a mensagem; e_priv sao 32 bytes aleatorios.
 * Devolve o tamanho escrito, ou -1 (chave remota de ordem pequena). */
long noise_ik_write1(noise_hs *hs, const uint8_t e_priv[32],
                     const uint8_t *payload, size_t len, uint8_t *out);
/* respondedor: le a 1a mensagem; hs->rs fica com a chave do iniciador.
 * payload_out precisa de len - 96 bytes. Devolve o tamanho do payload ou -1. */
long noise_ik_read1(noise_hs *hs, const uint8_t *msg, size_t len, uint8_t *payload_out);
/* respondedor: escreve a 2a mensagem e separa as chaves de transporte */
long noise_ik_write2(noise_hs *hs, const uint8_t e_priv[32],
                     const uint8_t *payload, size_t len, uint8_t *out,
                     noise_cipher *send, noise_cipher *recv);
/* iniciador: le a 2a mensagem e separa as chaves de transporte */
long noise_ik_read2(noise_hs *hs, const uint8_t *msg, size_t len, uint8_t *payload_out,
                    noise_cipher *send, noise_cipher *recv);

/* transporte: out tem len + 16 bytes (cifrar) ou len - 16 (decifrar).
 * decrypt devolve o tamanho do texto claro ou -1. Nao pode haver alias. */
size_t noise_encrypt(noise_cipher *c, const uint8_t *in, size_t len, uint8_t *out);
long   noise_decrypt(noise_cipher *c, const uint8_t *in, size_t len, uint8_t *out);

void noise_public_key(uint8_t pub[32], const uint8_t priv[32]);
void noise_wipe(void *p, size_t n);

#endif
