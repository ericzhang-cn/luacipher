#ifndef BASE64_H_
#define BASE64_H_

void base64_encode(const char* in, int in_len, char* out);

void base64_decode(const char* in, int in_len, char* out, int* out_len);

#endif
