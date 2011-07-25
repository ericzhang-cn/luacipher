#include <stdlib.h>
#include <string.h>

#include "crypto/base64.h"
#include "crypto/des.h"

#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"

#define LUA_LIB
#define BUFFSIZE 65536

static int b64_encode (lua_State *L) {
    const char* in = luaL_checkstring(L, 1);
    int in_len = lua_strlen(L, 1);
    int out_len;
    char out[BUFFSIZE];

    base64_encode(in, in_len, out);
    out_len = strlen(out);
    lua_pushlstring(L, out, out_len);
    return 1;
}

static int b64_decode (lua_State *L) {
    const char* in = luaL_checkstring(L, 1);
    int in_len = lua_strlen(L, 1);
    int out_len;
    char out[BUFFSIZE];

    base64_decode(in, in_len, out, &out_len);
    lua_pushlstring(L, out, out_len);
    return 1;
}

static int des_encrypt (lua_State *L) {
    const char* in = luaL_checkstring(L, 1);
    const char* key = luaL_checkstring(L, 2);
    int in_len = lua_strlen(L, 1);
    int out_len = in_len % 8 == 0 ? in_len : in_len + (8 - in_len % 8);
    char out[out_len + 1];

    des_ecb_encrypt(in, out, in_len, key);
    lua_pushlstring(L, out, out_len);
    return 1;
}

static int des_decrypt (lua_State *L) {
    const char* in = luaL_checkstring(L, 1);
    const char* key = luaL_checkstring(L, 2);
    int in_len = lua_strlen(L, 1);
    int out_len = in_len;
    char out[out_len + 1];

    des_ecb_decrypt(in, out, in_len, key);
    lua_pushlstring(L, out, out_len);
    return 1;
}

static const luaL_Reg luacipher[] = {
    {"b64_encode", b64_encode},
    {"b64_decode", b64_decode},
    {"des_encrypt", des_encrypt},
    {"des_decrypt", des_decrypt},
    {NULL, NULL}
};

/*
** Open luacipher library
*/
LUALIB_API int luaopen_luacipher (lua_State *L) {
    luaL_register(L, "luacipher", luacipher);
    return 1;
}
