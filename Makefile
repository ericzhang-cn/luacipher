LUA_CFLAGS=`pkg-config lua5.1 --cflags`

all: luacipher.so

luacipher.so: base64.c des.c luacipher.c
	gcc -shared -O3 luacipher.o base64.o des.o -o luacipher.so

base64.c:
	gcc -O3 -o base64.o -c src/crypto/base64.c

des.c:
	gcc -O3 -o des.o -c src/crypto/des.c

luacipher.c:
	gcc $(LUA_CFLAGS) -O3 -o luacipher.o -c src/luacipher.c

clean:
	rm *.o *.so
