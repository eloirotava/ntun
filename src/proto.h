/* Protocolo do ntun, sobre TCP:
 *
 *   quadro = tamanho (u16, big-endian) + mensagem Noise
 *
 * 1. roteador -> VPS: 1a mensagem do Noise_IK, payload = versao (1 byte)
 * 2. VPS -> roteador: 2a mensagem, payload vazio
 * 3. dai em diante, mensagens de transporte cujo texto claro e
 *    tipo (1 byte) + dados.
 *
 * Cada conexao TCP leva uma sessao so (como o rtun): o roteador deixa uma
 * conexao em espera; quando alguem conecta na porta dele na VPS, a VPS manda
 * GO e o roteador liga a conexao ao servico local.
 *
 * READY: so depois dele a VPS considera a conexao em espera. Uma 1a mensagem
 * repetida por um atacante passa no handshake, mas ele nao tem as chaves de
 * transporte para mandar o READY: nao ocupa vaga. */
#ifndef NTUN_PROTO_H
#define NTUN_PROTO_H

#define NTUN_PROLOGUE     "ntun 2" /* 2: BLAKE2s */
#define NTUN_VERSION      2
#define NTUN_DEFAULT_PORT 8222

enum {
	T_READY = 1, /* roteador -> VPS: handshake concluido, conexao em espera */
	T_GO    = 2, /* VPS -> roteador: alguem conectou, ligar ao servico local */
	T_DATA  = 3, /* dados, nos dois sentidos */
	T_CLOSE = 4, /* fim da sessao, nos dois sentidos */
	T_PING  = 5, /* qualquer lado; responde-se com PONG */
	T_PONG  = 6,
};

#define DATA_MAX  8192
#define MSG_MAX   (1 + DATA_MAX + 16)
#define FRAME_MAX (2 + MSG_MAX)

#define PING_S       25 /* ping sempre, mesmo com trafego */
#define DEAD_S       75 /* nada recebido (nem o pong) por isso: conexao morta */
#define HANDSHAKE_S  30 /* prazo do handshake inteiro */
#define IO_TIMEOUT_S 15 /* prazo de cada leitura/escrita bloqueante */

#endif
