CC=gcc
CFLAGS=-Wall -O3
LUA_CFLAGS=`pkg-config lua5.1 --cflags`
SRC_PATH=src/
CRYPTO_PATH=$(SRC_PATH)crypto/

all:
	$(CC) $(CFLAGS) $(LUA_CFLAGS) -shared $(SRC_PATH)luacipher.c $(CRYPTO_PATH)base64.c $(CRYPTO_PATH)des.c -o luacipher.so

clean:
	rm -f *.o *.so
