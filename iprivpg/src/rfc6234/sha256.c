#include "sha256.h"

static int SHA224_256AddLength(SHA256Context *context, unsigned int length);
static int SHA384_512AddLength(SHA512Context *context, unsigned int length);

#include "sha224-256.c"
#include "sha384-512.c"

static int SHA224_256AddLength(SHA256Context *context, unsigned int length)
{
    uint32_t addTemp;
    return SHA224_256AddLengthM(context, length);
}
static int SHA384_512AddLength(SHA512Context *context, unsigned int length)
{
    uint64_t addTemp;
    return SHA384_512AddLengthM(context, length);
}

void sha256_init(SHA256_CTX* ctx)
{
    SHA256Reset(ctx);
}

void sha256_update(SHA256_CTX* ctx,const unsigned char* data,size_t len)
{
    SHA256Input(ctx,data,len);
}

void sha256_final(SHA256_CTX* ctx,unsigned char* hash)
{
    SHA256Result(ctx,hash);
}
