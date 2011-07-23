#include <stdlib.h>
#include <stdio.h>

#include "des.h"

/* 获取一个字节中某一位的数据 */
static int get_bit(byte b, int pos) {
    return (b & byte_map[pos]) == 0x00 ? 0 : 1;
}

/* 设置一个字节中某一位的数据 */
static void set_bit(byte *b, int pos, int value) {
    *b = (value == 0) ? *b & byte_set0_map[pos] : *b | byte_set1_map[pos];
}

/* 根据指定映射表置换 */
static void mapping(byte in[], byte out[], int mtable[], int size) {
    int i, j, bit, map_value, b, pos;
    
    for(i=0; i<size; i++) {
        for(j=0; j<8; j++) {
            map_value = mtable[i * 8 + j] - 1;
            b = map_value / 8;
            pos = map_value % 8;
            bit = get_bit(in[b], pos);
            set_bit(&out[i], j, bit);
        }
    }
}

/* 密钥初始置换(PC1)，使用PC1映射表将64位密钥置换56位 */
static void mapping_pc1(byte key_in[], byte key_out[]) {
    mapping(key_in, key_out, pc1_map, 7);
}

/* 密钥Key Schedule置换(PC2)，使用PC2映射表将56位密钥置换48位 */
static void mapping_pc2(byte key_in[], byte key_out[]) {
    mapping(key_in, key_out, pc2_map, 6);
}

/* 用于Key Schedule生成过程中的循环移位 */
static void shift_key(byte key[], int round) {
    int shift = key_shift_map[round];
    int bit1, bit2, bit3, bit4, i;

    if(shift == 1) {
        bit1 = get_bit(key[0], 0);
        bit2 = get_bit(key[3], 4);
        
        for(i=0; i<7; i++) {
            key[i] << 1;
            set_bit(&key[i], 7, get_bit(key[i + 1], 0));
        }

        set_bit(&key[3], 3, bit1);
        set_bit(&key[6], 7, bit2);
    } else if(shift == 2) {
        bit1 = get_bit(key[0], 0);
        bit2 = get_bit(key[0], 1);
        bit3 = get_bit(key[3], 4);
        bit4 = get_bit(key[3], 5);
        
        for(i=0; i<7; i++) {
            key[i] << 2;
            set_bit(&key[i], 6, get_bit(key[i + 1], 0));
            set_bit(&key[i], 7, get_bit(key[i + 1], 1));
        }

        set_bit(&key[3], 2, bit1);
        set_bit(&key[3], 3, bit2);
        set_bit(&key[6], 6, bit3);
        set_bit(&key[6], 7, bit4);
    }
}

/* 生成Key Schedule */
void gen_key_schedule(byte key[], byte schedule[][6]) {
    byte choice1_key[7];
    int i;
    mapping_pc1(key, choice1_key);

    for(i=0; i<16; i++) {
        shift_key(choice1_key, i);
        mapping_pc2(choice1_key, schedule[i]);
    }
}

int main() {
    int i, j;
    byte key[] = "87654321";
    byte schedule[16][6];
    gen_key_schedule(key, schedule);

    for(i=0; i<16; i++) {
        for(j=0; j<6; j++) {
            printf("%x ", schedule[i][j]);
        }
        printf("\n");
    }
}
