/* Pecas comuns dos clientes (ntun, rtun, wsudp), sobre sys.h. */
#ifndef NTUN_UTIL_H
#define NTUN_UTIL_H

#include "sys.h"

int      hexval(char c);
int      unhex32(uint8_t out[32], const char *h);
unsigned atou(const char *s);
void     addr4(struct sockaddr_in *a, const uint8_t ip[4], unsigned port);
int      parse_ip4(uint8_t ip[4], const char *s);
int      random_bytes(uint8_t *b, size_t n);   /* getrandom ou /dev/urandom */
int      write_all(int fd, const uint8_t *b, size_t n);
int      read_all(int fd, uint8_t *b, size_t n, long deadline);
void     set_timeout(int fd, int opt, long sec);
/* registro A (ou IP literal), perguntando ao 1o nameserver do resolv.conf */
int      dns_resolve(const char *host, uint8_t ip[4]);
/* TCP com prazo de leitura/escrita/connect e keepalive (~1 min); fd ou -1 */
int      tcp_open(const struct sockaddr_in *a, long timeout_s);
/* base64 (url sem preenchimento, ou padrao com '='); devolve o tamanho */
size_t   b64(char *out, const uint8_t *in, size_t n, int url);

#endif
