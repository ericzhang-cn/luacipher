#ifndef DES_H_
#define DES_H_

typedef unsigned char byte;

void des_ecb_encrypt(const byte *in, byte *out, int inl, const byte *key);

void des_ecb_decrypt(const byte *in, byte *out, int inl, const byte *key);

#endif
