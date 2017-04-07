/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#ifndef __IPRIV_H
#define __IPRIV_H

#include <stdarg.h>
#include "libipriv.h"

// maximum data size
#ifdef WITH_2048_KEYS
#define MAX_MPI_BITS			2048
#else
#define MAX_MPI_BITS			1024
#endif
#define	MAX_MPI_LENGTH			(MAX_MPI_BITS/8)
#define	HALF_MPI_LENGTH			(MAX_MPI_LENGTH/2)
#define MD5_DIGEST_SIZE			16
#define SHA256_DIGEST_SIZE		32

#define MAX_EXTRA_DATA_LENGTH		32
#define MAX_MD_LOW_SIZE			2

// key type
#define IPRIV_KEY_TAG_SECRET		5
#define IPRIV_KEY_TAG_PUBLIC		6

// symmetric key types
#define IPRIV_SYMM_IDEA			1

typedef struct
{
	short version;
	short type;
	short bits;
	unsigned long keyserial;
	char userid[MAX_USERID_LENGTH+1];
	unsigned long timestamp;
	unsigned char extra[MAX_EXTRA_DATA_LENGTH];
	short extra_len;
	short alg;
	short hash_alg;
	unsigned char md_low[MAX_MD_LOW_SIZE];
	unsigned char mpi[MAX_MPI_LENGTH];
}IPRIV_SIGNATURE;


typedef struct
{
	short version;
	short type;
	short bits;
	unsigned long keyserial;
	char userid[MAX_USERID_LENGTH+1];
	unsigned long timestamp;
	int validity;
	short alg;
	unsigned char modulus[MAX_MPI_LENGTH];
	unsigned char publicExponent[MAX_MPI_LENGTH];
	unsigned char exponent[MAX_MPI_LENGTH];
	unsigned char prime1[HALF_MPI_LENGTH];
	unsigned char prime2[HALF_MPI_LENGTH];
	unsigned char coefficient[MAX_MPI_LENGTH];
}IPRIV_KEY_BODY;

typedef struct
{
	const char* ptr;
	int len;
}IPRIV_POSITION;

typedef struct
{
	short type;
	short is_ready;
	int error;
	void* data;
	int (*ctrl) (int cmd,va_list ap);
	int (*secret_key_new) (IPRIV_KEY_BODY* src,IPRIV_KEY* k);
	int (*secret_key_delete) (IPRIV_KEY* k);
	int (*public_key_new) (IPRIV_KEY_BODY* src,IPRIV_KEY* k);
	int (*public_key_delete) (IPRIV_KEY* k);
	int (*secret_key_encrypt) (unsigned char* src,int nsrc,unsigned char* dst,int ndst,IPRIV_KEY* k);
	int (*public_key_decrypt_and_verify) (unsigned char* src,int nsrc,unsigned char* dgst,int ndgst,IPRIV_KEY* k);
	int (*secret_key_export) (IPRIV_KEY_BODY* dst,IPRIV_KEY* k);
	int (*public_key_export) (IPRIV_KEY_BODY* dst,IPRIV_KEY* k);
	int (*secret_key_import) (IPRIV_KEY_BODY* src);
	int (*public_key_import) (IPRIV_KEY_BODY* src);
	int (*genkey) (IPRIV_KEY* sec,IPRIV_KEY* pub,int bits);
	int (*gen_random_bytes) (unsigned char* dst,int ndst);
	int (*public_key_encrypt) (unsigned char* src,int nsrc,unsigned char* dst,int ndst,IPRIV_KEY* k);
	int (*secret_key_decrypt) (unsigned char* src,int nsrc,unsigned char* dst,int ndst,IPRIV_KEY* k);
}IPRIV_ENGINE;

// одни движки могут вызывать реализацию других движков
extern IPRIV_ENGINE crypt_eng_list[IPRIV_MAX_ENG_NUM];


int Crypt_ReadSecretKey(const char* src,int nsrc,const char* passwd,IPRIV_KEY_BODY* key);
int Crypt_ReadSecretKey2(const char* src,int nsrc,const char* passwd,IPRIV_KEY_BODY* key);
int Crypt_WriteSecretKey(char* dst,int ndst,const char* passwd,IPRIV_KEY_BODY* key,unsigned char* iv,int niv);
int Crypt_SignPacket(const char* src,int nsrc,IPRIV_KEY* key,char* dst,int ndst,const char* pubuserid,IPRIV_SIGNATURE* sig,IPRIV_ENGINE* eng,int alg);
int Crypt_ReadPublicKey(const char* src,int nsrc,unsigned long keyserial,IPRIV_KEY_BODY* key,IPRIV_KEY* cakey,IPRIV_ENGINE* eng);
int Crypt_ReadPublicKey2(const char* src,int nsrc,IPRIV_KEY_BODY* key);
int Crypt_WritePublicKey(char* dst, int ndst, IPRIV_KEY_BODY* key, IPRIV_KEY* cakey, IPRIV_ENGINE* eng, IPRIV_ENGINE * ca_eng);
int Crypt_VerifyPacket(const char* src,int nsrc,const char* sigsrc,int nsigsrc,IPRIV_KEY* key,const char* pubuserid,IPRIV_SIGNATURE* sig,IPRIV_ENGINE* eng);


#endif
