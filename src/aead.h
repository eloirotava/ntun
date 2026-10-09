/* ChaCha20-Poly1305 (RFC 8439) compacto. ChaCha com os rounds em laco;
 * Poly1305 no estilo do TweetNaCl (17 limbs de 8 bits em u32: nada de
 * multiplicacao de 64 bits, cara no MIPS de 32 bits). */
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
