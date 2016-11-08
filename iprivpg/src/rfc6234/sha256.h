#ifndef SHA256_H
#define SHA256_H

#include "sha.h"
#include <sys/types.h>

typedef SHA256Context SHA256_CTX;

#ifdef __cplusplus
extern "C" {
#endif

void sha256_init(SHA256_CTX* ctx);
void sha256_update(SHA256_CTX* ctx,const unsigned char* data,size_t len);
void sha256_final(SHA256_CTX* ctx,unsigned char* hash);

#ifdef __cplusplus
}
#endif

#endif   // SHA256_H
