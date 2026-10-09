# Clientes em C: ntun (Noise), rtun e wsudp (TLS 1.3 + WebSocket do wstunnel),
# e o servidor do ntun.
#
#   make host                  tudo no PC (libc) + testes
#   make mips ARCH=mipsel|mips [MIPS16=1]
#                              clientes sem libc para o roteador:
#                              build/<prog>-<arch>[-16]
#   rtun: RTUN_DEF='-DRTUN_PREFIX="rev-..." -DRTUN_PORT=22101 -DRTUN_LOCAL=22'

CC      ?= gcc
CFLAGS  ?= -Os -Wall -Wextra
ARCH    ?= mipsel
RTUN_DEF ?=

# sha2.c: o c25519.c tem a verificacao Ed25519 (so o rtun/wsudp usam; no
# MIPS o --gc-sections tira, no PC precisa ligar)
NOISE   = src/noise.c src/blake2s.c src/c25519.c src/aead.c src/sha2.c
TLS     = src/tls13.c src/ws.c src/sha2.c src/c25519.c src/aead.c
COMMON  = src/util.c

SRC_ntun  = src/client.c $(NOISE) $(COMMON)
SRC_rtun  = src/rtun.c $(TLS) $(COMMON)
SRC_wsudp = src/wsudp.c $(TLS) $(COMMON)
SRC_tls_live = test/tls_live.c src/tls13.c src/sha2.c src/c25519.c src/aead.c $(COMMON)
SRC_bench = test/bench.c src/c25519.c src/aead.c

# MIPS: estatico, sem libc, sem PIC; so mips.S fica em MIPS32 normal.
# Sem -msoft-float: os cabecalhos da glibc do Debian nao aceitam, e o codigo
# nao usa ponto flutuante.
MIPS_FLAGS = -Os -Wall -Wextra -mips32r2 -mno-abicalls -fno-pic -G0 \
	-ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables \
	-ffunction-sections -fdata-sections -fno-tree-loop-distribute-patterns
MIPS_LD    = -static -nostdlib -Wl,-z,noexecstack -Wl,--gc-sections -Wl,-e,__start -Wl,--build-id=none -Wl,-z,norelro
ifeq ($(MIPS16),1)
MIPS_FLAGS += -mips16 -minterlink-mips16
SUF = -16
endif
STRIP_R = -R .comment -R .pdr -R .mdebug.abi32 -R .MIPS.abiflags -R .reginfo -R .gnu.attributes

host: build/ntun build/rtun build/wsudp build/ntun-server build/vectors build/blake2s_dump \
	build/sha_dump build/crypto_cmp build/tls_live

build/ntun build/rtun build/wsudp build/tls_live: build/%: src/*.h | build
	$(CC) $(CFLAGS) $(if $(filter rtun,$*),$$(echo '$(RTUN_DEF)')) -o $@ $(SRC_$*) src/sys_libc.c

build/ntun-server: src/server.c $(NOISE) src/*.h | build
	$(CC) $(CFLAGS) -o $@ src/server.c $(NOISE)

build/vectors: test/vectors.c $(NOISE) | build
	$(CC) $(CFLAGS) -o $@ test/vectors.c $(NOISE)

build/blake2s_dump: test/blake2s_dump.c src/blake2s.c | build
	$(CC) $(CFLAGS) -o $@ test/blake2s_dump.c src/blake2s.c

build/sha_dump: test/sha_dump.c src/sha2.c | build
	$(CC) $(CFLAGS) -o $@ test/sha_dump.c src/sha2.c

# a Monocypher so entra aqui, como referencia
build/crypto_cmp: test/crypto_cmp.c src/c25519.c src/aead.c src/sha2.c vendor/*.c | build
	$(CC) $(CFLAGS) -o $@ test/crypto_cmp.c src/c25519.c src/aead.c src/sha2.c vendor/monocypher.c vendor/monocypher-ed25519.c

mips: | build
	for p in ntun rtun wsudp tls_live bench; do \
	  $(ARCH)-linux-gnu-gcc $(MIPS_FLAGS) $(MIPS_LD) $$( [ $$p = rtun ] && echo '$(RTUN_DEF)' ) \
	    -o build/$$p-$(ARCH)$(SUF) $$(make -s --no-print-directory srcs P=$$p) src/sys_nolibc.c src/mips.S -lgcc || exit 1; \
	  cp build/$$p-$(ARCH)$(SUF) build/$$p-$(ARCH)$(SUF).elf; \
	  $(ARCH)-linux-gnu-strip -s $(STRIP_R) build/$$p-$(ARCH)$(SUF); \
	done

srcs:
	@echo $(SRC_$(P))

build:
	mkdir -p build

clean:
	rm -rf build
.PHONY: host mips srcs clean
