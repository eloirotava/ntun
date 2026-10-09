/* Velocidade do AEAD e do X25519 no roteador (sem libc, como o cliente).
 * Cifra blocos de 8 KB (o DATA_MAX do ntun) por 5 s e imprime KB/s. */
#include "../src/sys.h"
#include "../src/aead.h"
#include "../src/c25519.h"

static void put(const char *s, long v, const char *u)
{
	char b[64];
	int n = 0;
	while (*s) b[n++] = *s++;
	char d[20];
	int k = 0;
	do d[k++] = (char)('0' + v % 10); while ((v /= 10) && k < 19);
	while (k) b[n++] = d[--k];
	while (*u) b[n++] = *u++;
	b[n] = 0;
	x_log(b);
}

int main(void)
{
	static uint8_t buf[8192 + 16];
	uint8_t key[32] = { 1 }, nonce[12] = { 2 }, pt[32] = { 3 }, out[32];
	long t0 = x_now();
	while (x_now() == t0) {}
	t0 = x_now();
	long bytes = 0;
	while (x_now() - t0 < 5) {
		aead_seal(buf, key, nonce, 0, 0, buf, 8192);
		bytes += 8192;
	}
	put("chacha20-poly1305: ", bytes / 5 / 1024, " KB/s");
	t0 = x_now();
	while (x_now() == t0) {}
	t0 = x_now();
	long n = 0;
	while (x_now() - t0 < 5) {
		x25519(out, pt, out);
		n++;
	}
	put("x25519: ", n * 1000 / 5, " por 1000 s");
	return 0;
}
