/*
LuaCipher is a LUA extension that can be used to process common cryptographic algorithms. 

==============================================================================================
copyright 2011 Eric Zhang. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are
permitted provided that the following conditions are met:

    1. Redistributions of source code must retain the above copyright notice, this list of
       conditions and the following disclaimer.

    2. Redistributions in binary form must reproduce the above copyright notice, this list
       of conditions and the following disclaimer in the documentation and/or other materials
       provided with the distribution.

THIS SOFTWARE IS PROVIDED BY ERIC ZHANG ''AS IS'' AND ANY EXPRESS OR IMPLIED
WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL ERIC ZHANG OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those of the
authors and should not be interpreted as representing official policies, either expressed
or implied, of Eric Zhang. 
==============================================================================================
*/

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

static int tri_des_encrypt (lua_State *L) {
    const char* in = luaL_checkstring(L, 1);
    const char* key1 = luaL_checkstring(L, 2);
    const char* key2 = luaL_checkstring(L, 3);
    const char* key3 = luaL_checkstring(L, 4);
    int in_len = lua_strlen(L, 1);
    int out_len = in_len % 8 == 0 ? in_len : in_len + (8 - in_len % 8);
    char out1[out_len + 1], out2[out_len + 1], out3[out_len + 1];

    des_ecb_encrypt(in, out1, in_len, key1);
    des_ecb_encrypt(out1, out2, out_len, key2);
    des_ecb_encrypt(out2, out3, out_len, key3);
    lua_pushlstring(L, out3, out_len);
    return 1;
}

static int tri_des_decrypt (lua_State *L) {
    const char* in = luaL_checkstring(L, 1);
    const char* key1 = luaL_checkstring(L, 2);
    const char* key2 = luaL_checkstring(L, 3);
    const char* key3 = luaL_checkstring(L, 4);
    int in_len = lua_strlen(L, 1);
    int out_len = in_len;
    char out1[out_len + 1], out2[out_len + 1], out3[out_len + 1];

    des_ecb_decrypt(in, out1, in_len, key3);
    des_ecb_decrypt(out1, out2, out_len, key2);
    des_ecb_decrypt(out2, out3, out_len, key1);
    lua_pushlstring(L, out3, out_len);
    return 1;
}

static const luaL_Reg luacipher[] = {
    {"b64_encode", b64_encode}, /* Base64 encode */
    {"b64_decode", b64_decode}, /* Base64 decode */
    {"des_encrypt", des_encrypt}, /* DES encrypt */
    {"des_decrypt", des_decrypt}, /* DES decode */
    {"tri_des_encrypt", tri_des_encrypt}, /* Triple DES encrypt */
    {"tri_des_decrypt", tri_des_decrypt}, /* Triple DES decrypt */
    {NULL, NULL}
};

/* Open luacipher library */
LUALIB_API int luaopen_luacipher (lua_State *L) {
    luaL_register(L, "luacipher", luacipher);
    return 1;
}
