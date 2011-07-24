#ifndef BASE64_H
#define BASE64_H

void base64_encode(const char* in, int in_len, char* out);

void base64_decode(const char* in, int in_len, char* out, int* out_len);

#endif
