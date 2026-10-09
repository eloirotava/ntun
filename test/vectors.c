/* Confere noise.c contra o vetor oficial do Cacophony para
 * Noise_IK_25519_ChaChaPoly_BLAKE2b: as duas mensagens de handshake, o hash
 * final e 4 mensagens de transporte, nos dois sentidos. */
#include <stdio.h>
#include <string.h>
#include "../src/noise.h"
#include "vector_ik.h"

static size_t unhex(uint8_t *out, const char *h)
{
	size_t n = strlen(h) / 2;
	for (size_t i = 0; i < n; i++) sscanf(h + 2 * i, "%2hhx", &out[i]);
	return n;
}

static int fails;
#define CHECK(c, msg) do { if (!(c)) { printf("FALHOU: %s\n", msg); fails++; } } while (0)

int main(void)
{
	uint8_t prologue[64], is[32], ie[32], irs[32], rs_[32], re[32], hh[64];
	uint8_t want[512], buf[512], pl[512];
	size_t plen = unhex(prologue, v_init_prologue);
	unhex(is, v_init_static);
	unhex(ie, v_init_ephemeral);
	unhex(irs, v_init_remote_static);
	unhex(rs_, v_resp_static);
	unhex(re, v_resp_ephemeral);
	unhex(hh, v_handshake_hash);

	noise_hs ini, rsp;
	noise_cipher i_send, i_recv, r_send, r_recv;
	noise_ik_init(&ini, 1, is, irs, prologue, plen);
	noise_ik_init(&rsp, 0, rs_, 0, prologue, plen);

	/* -> e, es, s, ss */
	size_t pn = unhex(pl, v_payload[0]);
	size_t cn = unhex(want, v_cipher[0]);
	long n = noise_ik_write1(&ini, ie, pl, pn, buf);
	CHECK(n == (long)cn && memcmp(buf, want, cn) == 0, "mensagem 1");
	uint8_t got[512];
	n = noise_ik_read1(&rsp, buf, cn, got);
	CHECK(n == (long)pn && memcmp(got, pl, pn) == 0, "leitura da mensagem 1");
	uint8_t ipub[32];
	noise_public_key(ipub, is);
	CHECK(memcmp(rsp.rs, ipub, 32) == 0, "estatica do iniciador no respondedor");

	/* <- e, ee, se */
	pn = unhex(pl, v_payload[1]);
	cn = unhex(want, v_cipher[1]);
	n = noise_ik_write2(&rsp, re, pl, pn, buf, &r_send, &r_recv);
	CHECK(n == (long)cn && memcmp(buf, want, cn) == 0, "mensagem 2");
	n = noise_ik_read2(&ini, buf, cn, got, &i_send, &i_recv);
	CHECK(n == (long)pn && memcmp(got, pl, pn) == 0, "leitura da mensagem 2");
	CHECK(memcmp(ini.h, hh, 64) == 0 && memcmp(rsp.h, hh, 64) == 0, "hash do handshake");

	/* transporte: alternando iniciador -> respondedor e de volta */
	for (int m = 2; m < V_NMSG; m++) {
		pn = unhex(pl, v_payload[m]);
		cn = unhex(want, v_cipher[m]);
		noise_cipher *tx = (m % 2 == 0) ? &i_send : &r_send;
		noise_cipher *rx = (m % 2 == 0) ? &r_recv : &i_recv;
		size_t e = noise_encrypt(tx, pl, pn, buf);
		CHECK(e == cn && memcmp(buf, want, cn) == 0, "transporte (cifrar)");
		n = noise_decrypt(rx, buf, cn, got);
		CHECK(n == (long)pn && memcmp(got, pl, pn) == 0, "transporte (decifrar)");
	}

	/* adulterado: tem que recusar */
	pn = unhex(pl, "abcd");
	size_t e = noise_encrypt(&i_send, pl, pn, buf);
	buf[0] ^= 1;
	CHECK(noise_decrypt(&r_recv, buf, e, got) < 0, "recusa mensagem adulterada");

	/* handshake com estatica errada no iniciador: o respondedor recusa */
	uint8_t wrong[32];
	memcpy(wrong, irs, 32);
	wrong[0] ^= 1;
	noise_ik_init(&ini, 1, is, wrong, prologue, plen);
	noise_ik_init(&rsp, 0, rs_, 0, prologue, plen);
	n = noise_ik_write1(&ini, ie, pl, pn, buf);
	CHECK(n < 0 || noise_ik_read1(&rsp, buf, (size_t)n, got) < 0, "recusa chave do servidor errada");

	printf(fails ? "%d falhas\n" : "vetor Cacophony IK/BLAKE2b: ok\n", fails);
	return fails != 0;
}
