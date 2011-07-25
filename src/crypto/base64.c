/*
The implementation of BASE64 algorithm(http://tools.ietf.org/html/rfc4648).

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

#include "base64.h"

void base64_encode(const char* in, int in_len, char* out) {
    int cblock = in_len / 3;
    int tail = in_len % 3;
    int counter = 0;
    unsigned char src[3], dest[4];
    int offset[4];

    static const char base64_en_map[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    while(counter < cblock) {
        src[0] = in[counter*3];
        src[1] = in[counter*3 + 1];
        src[2] = in[counter*3 + 2];

        offset[0] = (src[0] >> 2) & 0x3F; 
        offset[1] = ((src[0] << 4) | (src[1] >> 4)) & 0x3F;
        offset[2] = ((src[1] << 2) | (src[2] >> 6)) & 0x3F;
        offset[3] = (src[2]) & 0x3F;

        dest[0] = base64_en_map[offset[0]];
        dest[1] = base64_en_map[offset[1]];
        dest[2] = base64_en_map[offset[2]];
        dest[3] = base64_en_map[offset[3]];

        out[counter*4] = dest[0];
        out[counter*4 + 1] = dest[1];
        out[counter*4 + 2] = dest[2];
        out[counter*4 + 3] = dest[3];

        counter++;
    }

    switch(tail) {
        case 0:
            break;
        case 1:
            src[0] = in[counter*3];

            offset[0] = (src[0] >> 2) & 0x3F; 
            offset[1] = (src[0] << 4) & 0x3F;

            dest[0] = base64_en_map[offset[0]];
            dest[1] = base64_en_map[offset[1]];

            out[counter*4] = dest[0];
            out[counter*4 + 1] = dest[1];
            out[counter*4 + 2] = '=';
            out[counter*4 + 3] = '=';

            counter++;
            break;
        case 2:
            src[0] = in[counter*3];
            src[1] = in[counter*3 + 1];

            offset[0] = (src[0] >> 2) & 0x3F; 
            offset[1] = ((src[0] << 4) | (src[1] >> 4)) & 0x3F;
            offset[2] = (src[1] << 2) & 0x3F;

            dest[0] = base64_en_map[offset[0]];
            dest[1] = base64_en_map[offset[1]];
            dest[2] = base64_en_map[offset[2]];

            out[counter*4] = dest[0];
            out[counter*4 + 1] = dest[1];
            out[counter*4 + 2] = dest[2];
            out[counter*4 + 3] = '=';
            
            counter++;
            break;
    }

    out[counter*4] = '\0';
}

void base64_decode(const char* in, int in_len, char* out, int* out_len) {
    int cblock = in_len / 4;
    int counter = 0;
    unsigned char src[4], dest[3];
    int offset[4];
    
    static const char base64_de_map[] = {
        0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 62, 0, 0, 0, 63, 52, 53, 54,
        55, 56, 57, 58, 59, 60, 61, 0, 0, 0,
        0, 0, 0, 0, 0, 1, 2, 3, 4, 5,
        6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
        0, 0, 0, 0, 0, 0, 26, 27, 28, 29, 
        30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
        40, 41, 42, 43, 44, 45, 46, 47, 48, 49,
        50, 51, 0, 0, 0, 0, 0, 0, 0, 0
    };

    while(counter < cblock) {
        src[0] = in[counter*4];
        src[1] = in[counter*4 + 1];
        src[2] = in[counter*4 + 2];
        src[3] = in[counter*4 + 3];

        offset[0] = base64_de_map[src[0]]; 
        offset[1] = base64_de_map[src[1]]; 
        offset[2] = base64_de_map[src[2]]; 
        offset[3] = base64_de_map[src[3]]; 

        dest[0] = (offset[0] << 2) | (offset[1] >> 4);
        dest[1] = (offset[1] << 4) | (offset[2] >> 2);
        dest[2] = (offset[2] << 6) | offset[3];

        out[counter*3] = dest[0];
        out[counter*3 + 1] = dest[1];
        out[counter*3 + 2] = dest[2];

        counter++;
    }

    if(in[in_len - 2] == '=') {
        out[counter*3 - 2] = '\0';
        *out_len = counter*3 - 2;
    } else if(in[in_len - 1] == '=') {
        out[counter*3 - 1] = '\0';
        *out_len = counter*3 - 1;
    } else {
        out[counter*3] = '\0';
        *out_len = counter*3;
    }
}
