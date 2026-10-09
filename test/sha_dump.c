/* "tamanho sha256 sha512" de entradas de 0 a 300 bytes entregues em pedacos
 * irregulares; o CI confere com o hashlib do Python */
#include <stdio.h>
#include "../src/sha2.h"

int main(void)
{
	uint8_t d[300], a[32], b[64];
	for (int i = 0; i < 300; i++) d[i] = (uint8_t)(i * 7 + 3);
	for (int n = 0; n <= 300; n++) {
		int p = n / 3, q = n / 3 + n / 5;
		sha256_ctx x;
		sha512_ctx y;
		sha256_init(&x);
		sha512_init(&y);
		sha256_update(&x, d, (size_t)p), sha256_update(&x, d + p, (size_t)(q - p)), sha256_update(&x, d + q, (size_t)(n - q));
		sha512_update(&y, d, (size_t)p), sha512_update(&y, d + p, (size_t)(q - p)), sha512_update(&y, d + q, (size_t)(n - q));
		sha256_final(&x, a);
		sha512_final(&y, b);
		printf("%d ", n);
		for (int i = 0; i < 32; i++) printf("%02x", a[i]);
		printf(" ");
		for (int i = 0; i < 64; i++) printf("%02x", b[i]);
		printf("\n");
	}
	return 0;
}
