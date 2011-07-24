#include <stdlib.h>
#include <string.h>

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
            key[i] = key[i] << 1;
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
            key[i] = key[i] << 2;
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
static void gen_key_schedule(byte key[], byte schedule[][6]) {
    byte choice1_key[7];
    int i;
    
    mapping_pc1(key, choice1_key);
    for(i=0; i<16; i++) {
        shift_key(choice1_key, i);
        mapping_pc2(choice1_key, schedule[i]);
    }
}

/* 明文初始置换(IP) */
static void mapping_ip(byte data_in[], byte data_out[]) {
    mapping(data_in, data_out, ip_map, 8);
}

/* 明文初始逆置换(IP-1) */
static void mapping_ip_inverse(byte data_in[], byte data_out[]) {
    mapping(data_in, data_out, _ip_map, 8);
}

/* E盒扩展置换(E) */
static void mapping_e(byte data_in[], byte data_out[]) {
    mapping(data_in, data_out, e_map, 6);
}

/* P盒压缩置换(P) */
static void mapping_p(byte data_in[], byte data_out[]) {
    mapping(data_in, data_out, p_map, 4);
}

/* S盒映射 */
static void mapping_s(byte data_in[], byte data_out[]) {
    int i;
    byte row1, row2, col1, col2, col3, col4, row, col;
    byte out[8];

    for(i=0; i<8; i++) {
        row1 = get_bit(data_in[(i * 6) / 8], (i * 6) % 8);
        row2 = get_bit(data_in[(i * 6 + 5) / 8], (i * 6 + 5) % 8);
        col1 = get_bit(data_in[(i * 6 + 1) / 8], (i * 6 + 1) % 8);
        col2 = get_bit(data_in[(i * 6 + 2) / 8], (i * 6 + 2) % 8);
        col3 = get_bit(data_in[(i * 6 + 3) / 8], (i * 6 + 3) % 8);
        col4 = get_bit(data_in[(i * 6 + 4) / 8], (i * 6 + 4) % 8);

        row = (row1 << 1) | row2;
        col = (col1 << 3) | (col2 << 2) | (col3 << 1) | col4;

        out[i] = s_map[i][row][col];
    }

    for(i=0; i<4; i++) {
        data_out[i] = (out[i * 2] << 4) | out[i * 2 + 1];
    }
}

/* 加密函数F，用于每轮半侧32位数据加密 */
static void f(byte r_in[], byte r_out[], byte k[]) {
    byte medi1[6], medi2[4];
    int i;
    
    mapping_e(r_in, medi1);

    for(i=0; i<6; i++) {
        medi1[i] ^= k[i];
    }

    mapping_s(medi1, medi2);
    mapping_p(medi2, r_out);
}

/* 分组数据(64位)加密 */
static void enc_block(byte in[], byte out[], byte schedule[][6]) {
    byte medi1[8], medi2[4];
    byte l0[4], r0[4], l1[4], r1[4];
    int i, j;
    
    mapping_ip(in, medi1);

    memcpy(l0, &medi1[0], 4);
    memcpy(r0, &medi1[4], 4);

    for(i=0; i<16; i++) {
        memcpy(l1, r0, 4);

        f(r0, medi2, schedule[i]);
        
        for(j=0; j<4; j++) {
            r1[j] = l0[j] ^ medi2[j];
        }
        
        memcpy(l0, l1, 4);
        memcpy(r0, r1, 4);
    }

    memcpy(&medi1[4], l0, 4);
    memcpy(&medi1[0], r0, 4);

    mapping_ip_inverse(medi1, out);
}

/* 分组数据(64位)解密 */
static void dec_block(byte in[], byte out[], byte schedule[][6]) {
    byte medi1[8], medi2[4];
    byte l0[4], r0[4], l1[4], r1[4];
    int i, j;
    
    mapping_ip(in, medi1);

    memcpy(l0, &medi1[0], 4);
    memcpy(r0, &medi1[4], 4);

    for(i=15; i>=0; i--) {
        memcpy(l1, r0, 4);

        f(r0, medi2, schedule[i]);
        
        for(j=0; j<4; j++) {
            r1[j] = l0[j] ^ medi2[j];
        }
        
        memcpy(l0, l1, 4);
        memcpy(r0, r1, 4);
    }
   
    memcpy(&medi1[4], l0, 4);
    memcpy(&medi1[0], r0, 4);

    mapping_ip_inverse(medi1, out);
}

/* DES加密 */
void des_encrypt(byte *in, byte *out, int inl, byte key[]) {
    int block_nums = inl / 8;
    int tail_nums = inl % 8;
    int i;
    byte schedule[16][6];
    byte in_block[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte out_block[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    gen_key_schedule(key, schedule);

    for(i=0; i<block_nums; i++) {
        memcpy(in_block, &in[i * 8], 8);
        enc_block(in_block, out_block, schedule);
        memcpy(&out[i * 8], out_block, 8);
    }

    if(tail_nums > 0) {
        memcpy(in_block, &in[i * 8], tail_nums);
        enc_block(in_block, out_block, schedule);
        memcpy(&out[i * 8], out_block, 8);
    }
}

/* DES解密 */
void des_decrypt(byte *in, byte *out, int inl, byte key[]) {
    int block_nums = inl / 8;
    int i;
    byte schedule[16][6];
    byte in_block[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    byte out_block[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    gen_key_schedule(key, schedule);

    for(i=0; i<block_nums; i++) {
        memcpy(in_block, &in[i * 8], 8);
        dec_block(in_block, out_block, schedule);
        memcpy(&out[i * 8], out_block, 8);
    }
}
