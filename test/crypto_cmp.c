/* Confere c25519.c, aead.c e sha2.c contra a Monocypher (vendor/, so nos
 * testes) e contra os vetores dos RFCs 7748, 8439, 8032 e 8448. */
#include <stdio.h>
#include <string.h>
#include "../src/aead.h"
#include "../src/c25519.h"
#include "../vendor/monocypher.h"
#include "../vendor/monocypher-ed25519.h"
#include "../src/sha2.h"

static int fails;
#define CHECK(c, msg) do { if (!(c)) { printf("FALHOU: %s\n", msg); fails++; } } while (0)

static void unhex(uint8_t *o, const char *h)
{
	for (size_t i = 0; h[2 * i]; i++) sscanf(h + 2 * i, "%2hhx", &o[i]);
}

int main(void)
{
	/* RFC 7748, 5.2 e 6.1 */
	uint8_t k[32], u[32], w[32], o[32];
	unhex(k, "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
	unhex(u, "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
	unhex(w, "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
	x25519(o, k, u);
	CHECK(memcmp(o, w, 32) == 0, "x25519 rfc 7748 5.2");
	unhex(k, "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
	unhex(w, "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
	x25519_base(o, k);
	CHECK(memcmp(o, w, 32) == 0, "x25519 rfc 7748 6.1 (publica)");
	/* 1000 iteracoes do RFC 7748 5.2 (k = x25519(k, u); u = k antigo) */
	uint8_t kk[32] = { 9 }, uu[32] = { 9 }, t[32];
	for (int i = 0; i < 1000; i++) {
		x25519(t, kk, uu);
		memcpy(uu, kk, 32);
		memcpy(kk, t, 32);
	}
	unhex(w, "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51");
	CHECK(memcmp(kk, w, 32) == 0, "x25519 rfc 7748 5.2 (1000 iteracoes)");
	/* contra a Monocypher com chaves e pontos variados (inclusive u com o
	 * bit alto ligado, que o RFC manda ignorar) */
	for (int n = 0; n < 200; n++) {
		uint8_t a[32], p[32], r1[32], r2[32];
		for (int i = 0; i < 32; i++) {
			a[i] = (uint8_t)(i * 31 + n * 17 + 5);
			p[i] = (uint8_t)(i * 13 + n * 101 + 1);
		}
		x25519(r1, a, p);
		crypto_x25519(r2, a, p);
		CHECK(memcmp(r1, r2, 32) == 0, "x25519 contra a Monocypher");
		x25519_base(r1, a);
		crypto_x25519_public_key(r2, a);
		CHECK(memcmp(r1, r2, 32) == 0, "x25519_base contra a Monocypher");
	}

	/* RFC 8439, 2.8.2 */
	{
		uint8_t key[32], nonce[12], ad[12], c[200], want[200];
		const char *pt = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
		size_t n = strlen(pt);
		unhex(key, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f");
		unhex(nonce, "070000004041424344454647");
		unhex(ad, "50515253c0c1c2c3c4c5c6c7");
		aead_seal(c, key, nonce, ad, 12, (const uint8_t *)pt, n);
		unhex(want, "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116");
		unhex(want + n, "1ae10b594f09e26a7e902ecbd0600691");
		CHECK(memcmp(c, want, n + 16) == 0, "aead rfc 8439 2.8.2");
		uint8_t back[200];
		CHECK(aead_open(back, key, nonce, ad, 12, c, n + 16) == 0 && memcmp(back, pt, n) == 0, "aead abre o do rfc");
	}
	/* contra a Monocypher (modo IETF) em varios tamanhos, com e sem dados
	 * associados; e recusa de tag adulterada */
	for (size_t n = 0; n <= 300; n++) {
		uint8_t key[32], nonce[12], ad[40], m[300], c1[316], c2[300], mac[16], back[300];
		for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i * 7 + n);
		for (int i = 0; i < 12; i++) nonce[i] = (uint8_t)(i + n * 3);
		for (int i = 0; i < 40; i++) ad[i] = (uint8_t)(i * 5 + 1);
		for (size_t i = 0; i < n; i++) m[i] = (uint8_t)(i * 13 + 7);
		size_t adl = n % 41;
		aead_seal(c1, key, nonce, ad, adl, m, n);
		crypto_aead_ctx x;
		crypto_aead_init_ietf(&x, key, nonce);
		crypto_aead_write(&x, c2, mac, ad, adl, m, n);
		CHECK(memcmp(c1, c2, n) == 0 && memcmp(c1 + n, mac, 16) == 0, "aead contra a Monocypher");
		CHECK(aead_open(back, key, nonce, ad, adl, c1, n + 16) == 0 && memcmp(back, m, n) == 0, "aead abre");
		c1[n % (n + 16)] ^= 1;
		CHECK(aead_open(back, key, nonce, ad, adl, c1, n + 16) == -1, "aead recusa adulterado");
	}

	/* Ed25519, RFC 8032 7.1 teste 1 (mensagem vazia) */
	{
		uint8_t pk[32], sig[64];
		unhex(pk, "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
		unhex(sig, "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
		const uint8_t *parts[1] = { (const uint8_t *)"" };
		size_t lens[1] = { 0 };
		CHECK(ed25519_verify(pk, sig, parts, lens, 1) == 0, "ed25519 rfc 8032 teste 1");
		sig[63] ^= 0x10; /* s >= L ou outra assinatura: recusa */
		CHECK(ed25519_verify(pk, sig, parts, lens, 1) != 0, "ed25519 recusa assinatura alterada");
	}
	/* contra o Ed25519 da Monocypher: ela assina, nos verificamos */
	for (int n = 0; n < 30; n++) {
		uint8_t seed[32], sk[64], pk[32], sig[64], msg[200];
		for (int i = 0; i < 32; i++) seed[i] = (uint8_t)(i * 13 + n * 101 + 1);
		for (int i = 0; i < 200; i++) msg[i] = (uint8_t)(i * 3 + n);
		size_t ml = (size_t)n * 6;
		crypto_ed25519_key_pair(sk, pk, seed);
		crypto_ed25519_sign(sig, sk, msg, ml);
		const uint8_t *parts[2] = { msg, msg + ml / 2 };
		size_t lens[2] = { ml / 2, ml - ml / 2 };
		CHECK(ed25519_verify(pk, sig, parts, lens, 2) == 0, "ed25519 verifica a da Monocypher");
		uint8_t bad[64];
		memcpy(bad, sig, 64);
		bad[n % 32] ^= 1; /* R */
		CHECK(ed25519_verify(pk, bad, parts, lens, 2) != 0, "ed25519 recusa R alterado");
		memcpy(bad, sig, 64);
		bad[32 + n % 31] ^= 1; /* S */
		CHECK(ed25519_verify(pk, bad, parts, lens, 2) != 0, "ed25519 recusa S alterado");
		pk[n % 32] ^= 1;
		CHECK(ed25519_verify(pk, sig, parts, lens, 2) != 0, "ed25519 recusa chave alterada");
		pk[n % 32] ^= 1;
		if (ml) {
			msg[0] ^= 1;
			CHECK(ed25519_verify(pk, sig, parts, lens, 2) != 0, "ed25519 recusa mensagem alterada");
		}
	}

	/* HKDF do TLS 1.3: RFC 8448, secao 3 (do segredo compartilhado ao
	 * "s hs traffic" e o iv do servidor) */
	{
		uint8_t shared[32], hello[32], want[32], zeros[32] = {0}, empty[32], early[32], der[32], hs[32], s[32], iv[12], wiv[12];
		unhex(shared, "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
		unhex(hello, "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8");
		unhex(want, "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38");
		unhex(wiv, "5d313eb2671276ee13000b30");
		sha256_ctx x;
		sha256_init(&x);
		sha256_final(&x, empty);
		hmac_sha256(early, zeros, 32, zeros, 32, 0, 0);
		hkdf_label(der, early, "derived", empty, 32, 32);
		hmac_sha256(hs, der, 32, shared, 32, 0, 0);
		hkdf_label(s, hs, "s hs traffic", hello, 32, 32);
		CHECK(memcmp(s, want, 32) == 0, "tls13 rfc 8448 s hs traffic");
		hkdf_label(iv, s, "iv", 0, 0, 12);
		CHECK(memcmp(iv, wiv, 12) == 0, "tls13 rfc 8448 iv");
	}

	printf(fails ? "%d falhas\n" : "x25519, ed25519, chacha20-poly1305, sha2 e hkdf: ok (rfcs e Monocypher)\n", fails);
	return fails != 0;
}
