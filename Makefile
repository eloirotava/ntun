# ntun: cliente (roteador, sem libc) e servidor (VPS, libc).
#
#   make host                 cliente e servidor no PC (libc), mais o teste do vetor
#   make mipsel [MIPS16=1]    cliente para MIPS little-endian (Archer C5, MT7620A)
#   make mips   [MIPS16=1]    cliente para MIPS big-endian (N600, WDR3600)

CC      ?= gcc
CFLAGS  ?= -Os -Wall -Wextra
CRYPTO   = src/noise.c src/blake2s.c src/x25519.c src/aead.c
SRC_C    = src/client.c $(CRYPTO)

# cliente MIPS: estatico, sem libc, sem PIC; so mips.S fica em MIPS32 normal.
# Sem -msoft-float: os cabecalhos da glibc do Debian nao aceitam, e o codigo
# nao usa ponto flutuante.
MIPS_FLAGS = -Os -Wall -Wextra -mips32r2 -mno-abicalls -fno-pic -G0 \
	-ffreestanding -fno-builtin -fno-stack-protector -fno-asynchronous-unwind-tables \
	-ffunction-sections -fdata-sections -fno-tree-loop-distribute-patterns
MIPS_LD    = -static -nostdlib -Wl,--gc-sections -Wl,-e,__start -Wl,--build-id=none -Wl,-z,norelro
ifeq ($(MIPS16),1)
MIPS_FLAGS += -mips16 -minterlink-mips16
endif

host: build/ntun build/ntun-server build/vectors build/blake2s_dump build/crypto_cmp

build/ntun: $(SRC_C) src/sys_libc.c src/*.h | build
	$(CC) $(CFLAGS) -o $@ $(SRC_C) src/sys_libc.c

build/ntun-server: src/server.c $(CRYPTO) src/*.h | build
	$(CC) $(CFLAGS) -o $@ src/server.c $(CRYPTO)

build/vectors: test/vectors.c $(CRYPTO) | build
	$(CC) $(CFLAGS) -o $@ test/vectors.c $(CRYPTO)

# a Monocypher so entra aqui, como referencia
build/crypto_cmp: test/crypto_cmp.c src/x25519.c src/aead.c vendor/monocypher.c | build
	$(CC) $(CFLAGS) -o $@ test/crypto_cmp.c src/x25519.c src/aead.c vendor/monocypher.c

build/blake2s_dump: test/blake2s_dump.c src/blake2s.c | build
	$(CC) $(CFLAGS) -o $@ test/blake2s_dump.c src/blake2s.c

mipsel: | build
	mipsel-linux-gnu-gcc $(MIPS_FLAGS) $(MIPS_LD) -o build/ntun-mipsel$(if $(MIPS16),-16) \
		$(SRC_C) src/sys_nolibc.c src/mips.S -lgcc
	cp build/ntun-mipsel$(if $(MIPS16),-16) build/ntun-mipsel$(if $(MIPS16),-16).elf
	mipsel-linux-gnu-strip -s -R .comment -R .pdr -R .mdebug.abi32 -R .MIPS.abiflags -R .reginfo \
		-R .gnu.attributes build/ntun-mipsel$(if $(MIPS16),-16)

mips: | build
	mips-linux-gnu-gcc $(MIPS_FLAGS) $(MIPS_LD) -o build/ntun-mips$(if $(MIPS16),-16) \
		$(SRC_C) src/sys_nolibc.c src/mips.S -lgcc
	cp build/ntun-mips$(if $(MIPS16),-16) build/ntun-mips$(if $(MIPS16),-16).elf
	mips-linux-gnu-strip -s -R .comment -R .pdr -R .mdebug.abi32 -R .MIPS.abiflags -R .reginfo \
		-R .gnu.attributes build/ntun-mips$(if $(MIPS16),-16)

build:
	mkdir -p build

clean:
	rm -rf build
.PHONY: host mipsel mips clean
