
OPENSSL_LIB ?= ../openssl-argon2/
CC ?= gcc

CFLAGS ?= -DARGON2D

override CFLAGS += -std=c99 -O0 -Wall -Werror -Wno-unused-function -g3 \
                   -Iinclude -Isrc -I$(OPENSSL_LIB)/include

LDFLAGS += -L$(OPENSSL_LIB) -lcrypto

build: clean
	export LD_LIBRARY_PATH=$(OPENSSL_LIB); \
	$(CC) $(CFLAGS) $(LDFLAGS) ./main.c -o ./main

build-btest: clean
	export LD_LIBRARY_PATH=$(OPENSSL_LIB); \
	$(CC) $(CFLAGS) $(LDFLAGS) ./blake_mac_test.c -o ./main-blake

run: build
	export LD_LIBRARY_PATH=$(OPENSSL_LIB); \
	./main

gdb: build
	export LD_LIBRARY_PATH=$(OPENSSL_LIB); \
	gdb -tui ./main

valgrind: build
	export LD_LIBRARY_PATH=$(OPENSSL_LIB); \
	valgrind ./main

clean:
	rm -f ./main
