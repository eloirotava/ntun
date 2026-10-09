/* TLS 1.3 contra o servidor real (br.rotava.com, SNI wsudp.rotava.internal):
 * handshake com o certificado fixado, GET e resposta HTTP; e o mesmo com um
 * byte do certificado trocado, que tem que ser recusado. Usa so sys.h:
 * roda no PC e, sem libc, como MIPS no qemu. */
#include "../src/util.h"
#include "../src/tls13.h"
#include "../src/cert.h"

static tls_conn c;

static int conecta(const struct sockaddr_in *a, const uint8_t *cert, const char **err)
{
	int fd = tcp_open(a, 15);
	if (fd < 0) {
		*err = "tcp";
		return -1;
	}
	*err = tls_handshake(&c, fd, "wsudp.rotava.internal", cert, sizeof pinned_cert, pinned_key, x_now() + 30);
	return fd;
}

int main(void)
{
	uint8_t ip[4], bad[sizeof pinned_cert], buf[64];
	struct sockaddr_in a;
	const char *err;
	if (dns_resolve("br.rotava.com", ip)) { x_log("FALHOU: dns"); return 1; }
	addr4(&a, ip, 443);

	int fd = conecta(&a, pinned_cert, &err);
	if (fd < 0 || err) { x_log("FALHOU: handshake"); if (err) x_log(err); return 1; }
	static const char get[] = "GET / HTTP/1.1\r\nHost: wsudp.rotava.internal\r\nConnection: close\r\n\r\n";
	if (tls_write(&c, (const uint8_t *)get, sizeof get - 1)) { x_log("FALHOU: escrita"); return 1; }
	size_t n = 0;
	while (n < 8) {
		long r = tls_read(&c, buf + n, sizeof buf - n);
		if (r < 0) { x_log("FALHOU: leitura"); return 1; }
		n += (size_t)r;
	}
	x_close(fd);
	static const char want[] = "HTTP/1.1";
	for (int i = 0; i < 8; i++) if (buf[i] != (uint8_t)want[i]) { x_log("FALHOU: resposta"); return 1; }

	for (size_t i = 0; i < sizeof bad; i++) bad[i] = pinned_cert[i];
	bad[sizeof bad - 1] ^= 1;
	fd = conecta(&a, bad, &err);
	if (fd >= 0) x_close(fd);
	if (!err) { x_log("FALHOU: certificado errado aceito"); return 1; }
	x_log("tls ao vivo: ok (handshake, GET, certificado errado recusado)");
	return 0;
}
