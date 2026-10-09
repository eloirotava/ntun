/* WebSocket do wstunnel; ver ws.h */
#include "ws.h"
#include "util.h"

static size_t put(char *o, size_t n, const char *s)
{
	while (*s) o[n++] = *s++;
	return n;
}

long ws_request(char *out, size_t cap, const char *path, const char *host, const char *claims_tail)
{
	uint8_t key[16], id[16];
	char claims[200];
	size_t c = 0, n = 0, tl = 0;
	while (claims_tail[tl]) tl++;
	if (random_bytes(key, 16) || random_bytes(id, 16) || tl > 120) return -1;
	/* uuid v4 */
	id[6] = (uint8_t)((id[6] & 0x0f) | 0x40);
	id[8] = (uint8_t)((id[8] & 0x3f) | 0x80);
	c = put(claims, c, "{\"id\":\"");
	for (int i = 0; i < 16; i++) {
		if (i == 4 || i == 6 || i == 8 || i == 10) claims[c++] = '-';
		claims[c++] = "0123456789abcdef"[id[i] >> 4];
		claims[c++] = "0123456789abcdef"[id[i] & 15];
	}
	c = put(claims, c, claims_tail);
	static const char hdr[] = "{\"typ\":\"JWT\",\"alg\":\"HS256\"}";
	if (cap < 400 + 4 * c / 3) return -1;
	n = put(out, n, "GET ");
	n = put(out, n, path);
	n = put(out, n, " HTTP/1.1\r\nHost: ");
	n = put(out, n, host);
	n = put(out, n, "\r\nUpgrade: websocket\r\nConnection: upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ");
	n += b64(out + n, key, 16, 0);
	n = put(out, n, "\r\nSec-WebSocket-Protocol: v1, authorization.bearer.");
	n += b64(out + n, (const uint8_t *)hdr, sizeof hdr - 1, 1);
	out[n++] = '.';
	n += b64(out + n, (const uint8_t *)claims, c, 1);
	n = put(out, n, ".AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n\r\n");
	return (long)n;
}

size_t ws_frame(uint8_t *out, int opcode, const uint8_t *p, size_t n)
{
	size_t o = 2;
	out[0] = (uint8_t)(0x80 | opcode);
	if (n < 126) {
		out[1] = (uint8_t)(0x80 | n);
	} else if (n <= 0xffff) {
		out[1] = 0x80 | 126;
		out[2] = (uint8_t)(n >> 8), out[3] = (uint8_t)n;
		o = 4;
	} else {
		out[1] = 0x80 | 127;
		for (int i = 0; i < 8; i++) out[2 + i] = (uint8_t)((uint64_t)n >> (56 - 8 * i));
		o = 10;
	}
	for (int i = 0; i < 4; i++) out[o++] = 0; /* mascara zero */
	for (size_t i = 0; i < n; i++) out[o + i] = p[i];
	return o + n;
}

long ws_parse(const uint8_t *b, size_t len, size_t cap, int *op, size_t *off, size_t *plen)
{
	if (len < 2) return 0;
	if (b[1] & 0x80) return -1; /* servidor nao mascara */
	uint64_t n = b[1] & 0x7f;
	size_t o = 2;
	if (n == 126) {
		if (len < 4) return 0;
		n = (uint64_t)b[2] << 8 | b[3];
		o = 4;
	} else if (n == 127) {
		if (len < 10) return 0;
		n = 0;
		for (int i = 0; i < 8; i++) n = n << 8 | b[2 + i];
		o = 10;
	}
	if (n > cap - o) return -1;
	if (len < o + n) return 0;
	*op = b[0] & 0x0f;
	*off = o;
	*plen = (size_t)n;
	return (long)(o + n);
}
