/* ChaCha20-Poly1305 (RFC 8439). ChaCha com os rounds em laco (compacto);
 * Poly1305 com 5 limbs de 26 bits (rapido: 25 multu por bloco de 16 bytes). */
#ifndef NTUN_AEAD_H
#define NTUN_AEAD_H

#include <stddef.h>
#include <stdint.h>

/* out: len + 16 bytes (texto cifrado + tag). out pode ser in. */
void aead_seal(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
               const uint8_t *ad, size_t adl, const uint8_t *in, size_t len);
/* in: len bytes (texto cifrado + tag). Confere a tag antes de decifrar.
 * Devolve 0 ou -1 (tag errada; nada e escrito em out). out pode ser in. */
int aead_open(uint8_t *out, const uint8_t key[32], const uint8_t nonce[12],
              const uint8_t *ad, size_t adl, const uint8_t *in, size_t len);

void wipe(void *p, size_t n);

#endif
