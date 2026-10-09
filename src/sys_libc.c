/* sys.h pela libc: para rodar o cliente no PC (testes, sanitizers). */
#include "sys.h"
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/random.h>

#define R(x) do { long r_ = (long)(x); return r_ < 0 ? -errno : r_; } while (0)

long x_socket(int d, int t, int p) { R(socket(d, t, p)); }
long x_connect(int fd, const struct sockaddr_in *a) { R(connect(fd, (const struct sockaddr *)a, sizeof *a)); }
long x_setsockopt(int fd, int l, int o, const void *v, unsigned n) { R(setsockopt(fd, l, o, v, n)); }
long x_poll(struct pollfd *f, unsigned n, int ms) { R(poll(f, n, ms)); }
long x_read(int fd, void *b, size_t n) { R(read(fd, b, n)); }
long x_write(int fd, const void *b, size_t n) { R(write(fd, b, n)); }
long x_sendto(int fd, const void *b, size_t n, const struct sockaddr_in *a)
{
	R(sendto(fd, b, n, 0, (const struct sockaddr *)a, sizeof *a));
}
long x_recv(int fd, void *b, size_t n, int fl) { R(recv(fd, b, n, fl)); }
long x_recvfrom(int fd, void *b, size_t n, int fl, struct sockaddr_in *f)
{
	socklen_t l = sizeof *f;
	R(recvfrom(fd, b, n, fl, (struct sockaddr *)f, &l));
}
long x_bind(int fd, const struct sockaddr_in *a) { R(bind(fd, (const struct sockaddr *)a, sizeof *a)); }
long x_close(int fd) { R(close(fd)); }
long x_open(const char *p) { R(open(p, O_RDONLY | O_CLOEXEC)); }
long x_getrandom(void *b, size_t n) { R(getrandom(b, n, 0)); }
long x_now(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (long)t.tv_sec;
}
void x_sleep(unsigned s) { sleep(s); }
void x_log(const char *m)
{
	(void)!write(2, m, strlen(m));
	(void)!write(2, "\n", 1);
}
