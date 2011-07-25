#ifndef DES_H_
#define DES_H_

typedef unsigned char byte;

void des_encrypt(byte *in, byte *out, int inl, byte key[]);

void des_decrypt(byte *in, byte *out, int inl, byte key[]);

#endif
