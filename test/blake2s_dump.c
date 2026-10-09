/* imprime "tamanho hash" do BLAKE2s de entradas de 0 a 300 bytes, entregues
 * em pedacos irregulares; o CI confere com o hashlib do Python */
#include <stdio.h>
#include "../src/blake2s.h"

int main(void)
{
	uint8_t d[300], o[32];
	for (int i = 0; i < 300; i++) d[i] = (uint8_t)(i * 7 + 3);
	for (int n = 0; n <= 300; n++) {
		blake2s_ctx x;
		blake2s_init(&x);
		int a = n / 3, b = n / 3 + n / 5;
		blake2s_update(&x, d, (size_t)a);
		blake2s_update(&x, d + a, (size_t)(b - a));
		blake2s_update(&x, d + b, (size_t)(n - b));
		blake2s_final(&x, o);
		printf("%d ", n);
		for (int i = 0; i < 32; i++) printf("%02x", o[i]);
		printf("\n");
	}
	return 0;
}
