/* Cliente TLS 1.3 minimo (porte do tls13.zig): TLS_CHACHA20_POLY1305_SHA256,
 * X25519, e um unico certificado aceito (comparado byte a byte) cuja chave
 * Ed25519 confere o CertificateVerify. Sem datas, sem cadeia, sem retomada.
 * O ClientHello e o mesmo do rtun/wsudp em Zig: na rede nada muda.
 * Le um registro inteiro por vez: nada fica escondido do poll() alem do
 * texto claro ja decifrado (tls_pending). */
#ifndef NTUN_TLS13_H
#define NTUN_TLS13_H

#include <stddef.h>
#include <stdint.h>

#define TLS_MAX_PLAIN  16384
#define TLS_MAX_RECORD (TLS_MAX_PLAIN + 256)

typedef struct {
	int      fd;
	uint8_t  ckey[32], civ[12], csec[32];
	uint8_t  skey[32], siv[12], ssec[32];
	uint64_t cseq, sseq;
	size_t   pos, len; /* texto claro em rec[pos..len] */
	uint8_t  rec[5 + TLS_MAX_RECORD];
} tls_conn;

/* handshake bloqueante sobre um socket ja conectado; deadline em x_now().
 * Devolve 0 ou uma mensagem de erro curta. */
const char *tls_handshake(tls_conn *c, int fd, const char *host,
                          const uint8_t *cert, size_t cert_len,
                          const uint8_t cert_key[32], long deadline);
int  tls_write(tls_conn *c, const uint8_t *d, size_t n); /* 0 ou -1 */
/* le ate n bytes de dados; 0 = registro so de controle (nao e fim);
 * -1 = conexao acabou ou erro */
long tls_read(tls_conn *c, uint8_t *out, size_t n);
static inline int tls_pending(const tls_conn *c) { return c->pos < c->len; }

#endif
