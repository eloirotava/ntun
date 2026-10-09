/* WebSocket do lado do cliente, no dialeto do wstunnel v10: pedido de
 * upgrade com o destino num JWT (assinatura fixa: o servidor nao confere,
 * quem autoriza sao o caminho/prefixo e as regras dele) e quadros com o bit
 * de mascara e chave zero (o wstunnel nao desmascara). */
#ifndef NTUN_WS_H
#define NTUN_WS_H

#include <stddef.h>
#include <stdint.h>

/* pedido de upgrade; claims_tail e o JSON depois do id, ex.
 * "\",\"p\":\"ReverseTcp\",\"r\":\"127.0.0.1\",\"rp\":22101}". Tamanho ou -1. */
long   ws_request(char *out, size_t cap, const char *path, const char *host, const char *claims_tail);
/* quadro do cliente; out precisa de n + 14 bytes */
size_t ws_frame(uint8_t *out, int opcode, const uint8_t *p, size_t n);
/* quadro do servidor em b[0..len]: tamanho total se completo, 0 se falta,
 * -1 se invalido (mascarado ou maior que cap) */
long   ws_parse(const uint8_t *b, size_t len, size_t cap, int *op, size_t *off, size_t *plen);

#endif
