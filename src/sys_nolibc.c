/* sys.h direto no kernel (Linux MIPS o32), sem libc: so o que o cliente usa.
 * raw_syscall e __start estao em mips.S. */
#include "sys.h"
#include <asm/unistd.h>
#include <time.h>

long raw_syscall(long n, long a, long b, long c, long d, long e, long f);
#define S0(n)                raw_syscall(__NR_##n, 0, 0, 0, 0, 0, 0)
#define S3(n, a, b, c)       raw_syscall(__NR_##n, (long)(a), (long)(b), (long)(c), 0, 0, 0)
#define S6(n, a, b, c, d, e, f) \
	raw_syscall(__NR_##n, (long)(a), (long)(b), (long)(c), (long)(d), (long)(e), (long)(f))

long x_socket(int d, int t, int p) { return S3(socket, d, t, p); }
long x_connect(int fd, const struct sockaddr_in *a) { return S3(connect, fd, a, sizeof *a); }
long x_setsockopt(int fd, int l, int o, const void *v, unsigned n) { return S6(setsockopt, fd, l, o, v, n, 0); }
long x_poll(struct pollfd *f, unsigned n, int ms) { return S3(poll, f, n, ms); }
long x_read(int fd, void *b, size_t n) { return S3(read, fd, b, n); }
long x_write(int fd, const void *b, size_t n) { return S3(write, fd, b, n); }
long x_sendto(int fd, const void *b, size_t n, const struct sockaddr_in *a)
{
	return S6(sendto, fd, b, n, 0, a, sizeof *a);
}
long x_recv(int fd, void *b, size_t n, int fl) { return S6(recvfrom, fd, b, n, fl, 0, 0); }
long x_close(int fd) { return S3(close, fd, 0, 0); }
long x_open(const char *p) { return S3(open, p, O_RDONLY | O_CLOEXEC, 0); }
long x_getrandom(void *b, size_t n) { return S3(getrandom, b, n, 0); }

/* clock_gettime64 (kernel >= 5.1); senao o de 32 bits dos kernels antigos */
long x_now(void)
{
	long long t64[2];
	long t32[2];
	if (S3(clock_gettime64, CLOCK_MONOTONIC, t64, 0) == 0) return (long)t64[0];
	S3(clock_gettime, CLOCK_MONOTONIC, t32, 0);
	return t32[0];
}

/* pausa: poll sem descritores (nao depende de struct de tempo) */
void x_sleep(unsigned s) { S3(poll, 0, 0, (long)s * 1000); }

static size_t slen(const char *s) { size_t n = 0; while (s[n]) n++; return n; }

void x_log(const char *m)
{
	S3(write, 2, m, slen(m));
	S3(write, 2, "\n", 1);
}

/* o compilador pode chamar estas mesmo com -ffreestanding */
void *memcpy(void *d, const void *s, size_t n)
{
	unsigned char *a = d;
	const unsigned char *b = s;
	while (n--) *a++ = *b++;
	return d;
}

void *memmove(void *d, const void *s, size_t n)
{
	unsigned char *a = d;
	const unsigned char *b = s;
	if (a < b) while (n--) *a++ = *b++;
	else while (n--) a[n] = b[n];
	return d;
}

void *memset(void *d, int c, size_t n)
{
	unsigned char *a = d;
	while (n--) *a++ = (unsigned char)c;
	return d;
}

int memcmp(const void *x, const void *y, size_t n)
{
	const unsigned char *a = x, *b = y;
	for (; n; n--, a++, b++) if (*a != *b) return *a - *b;
	return 0;
}

/* deslocamentos de 64 bits que o gcc chama no MIPS de 32 bits. Os da libgcc
 * do Debian sao PIC (abicalls) e este binario nao e: melhor ter os nossos.
 * So deslocamentos de 32 bits aqui dentro (os de 64 chamariam a si mesmos). */
typedef unsigned long long u64;
typedef long long i64;

static u64 join(uint32_t hi, uint32_t lo) { return (u64)hi << 32 | lo; }

u64 __lshrdi3(u64 a, int b)
{
	uint32_t lo = (uint32_t)a, hi = (uint32_t)(a >> 32);
	if (b == 0) return a;
	if (b >= 32) return join(0, hi >> (b - 32));
	return join(hi >> b, lo >> b | hi << (32 - b));
}

u64 __ashldi3(u64 a, int b)
{
	uint32_t lo = (uint32_t)a, hi = (uint32_t)(a >> 32);
	if (b == 0) return a;
	if (b >= 32) return join(lo << (b - 32), 0);
	return join(hi << b | lo >> (32 - b), lo << b);
}

i64 __ashrdi3(i64 a, int b)
{
	uint32_t lo = (uint32_t)a;
	int32_t hi = (int32_t)(a >> 32);
	if (b == 0) return a;
	if (b >= 32) return (i64)join((uint32_t)(hi >> 31), (uint32_t)(hi >> (b - 32)));
	return (i64)join((uint32_t)(hi >> b), lo >> b | (uint32_t)hi << (32 - b));
}
