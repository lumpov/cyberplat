/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#ifdef _WIN32
#ifndef _WIN32_WCE
	#if !defined(_WIN32_WINNT)
		#if _MSC_VER > 1400 
			#define _WIN32_WINNT	0x0501
		#else
			#define _WIN32_WINNT	0x0400
		#endif /* _MSC_VER > 1400  */
	#endif /* !defined(_WIN32_WINNT) */
#endif /* _WIN32_WCE */
#include <windows.h>
#include <wincrypt.h>
#endif /* _WIN32 */

#include "eng_rsaref.h"
#include "i_stdlib.h"
#include "rsaref/i_global.h"
#include "rsaref/rsaref.h"
#include "libipriv.h"
#include <string.h>
#include "packet.h"
#include <time.h>

extern "C" {
#include "rsaref/rsa.h"
#include "rsaref/nn.h"
#include "rsaref/r_random.h"
}

/*
#include <stdio.h>
void dump_key(IPRIV_KEY_BODY& key);
void eng_rsaref_dump_sec_key(R_RSA_PRIVATE_KEY& key)
{
	printf("SECRET_KEY:\n");
	printf("\tBITS: %i\n",key.bits);
	printf("\tMODULUS: "); eng_rsaref_dump(key.modulus,sizeof(key.modulus));
	printf("\tPUBLIC_EXPONENT: "); eng_rsaref_dump(key.publicExponent,sizeof(key.publicExponent));
	printf("\tEXPONENT: "); eng_rsaref_dump(key.exponent,sizeof(key.exponent));
	printf("\tPRIME1: "); eng_rsaref_dump(key.prime[0],sizeof(key.prime[0]));
	printf("\tPRIME2: "); eng_rsaref_dump(key.prime[1],sizeof(key.prime[1]));
	printf("\tPRIME1EXP: "); eng_rsaref_dump(key.primeExponent[0],sizeof(key.primeExponent[0]));
	printf("\tPRIME2EXP: "); eng_rsaref_dump(key.primeExponent[1],sizeof(key.primeExponent[1]));
	printf("\tCOEFFICIENT: "); eng_rsaref_dump(key.coefficient,sizeof(key.coefficient));
}
void eng_rsaref_dump_pub_key(R_RSA_PUBLIC_KEY& key)
{
	printf("PUBLIC_KEY:\n");
	printf("\tBITS: %i\n",key.bits);
	printf("\tMODULUS: "); eng_rsaref_dump(key.modulus,sizeof(key.modulus));
	printf("\tEXPONENT: "); eng_rsaref_dump(key.exponent,sizeof(key.exponent));
}
*/




R_RANDOM_STRUCT eng_rsaref_random_struct;




int eng_rsaref_check_secret_key(R_RSA_PRIVATE_KEY * pkey)	// dynamic memory allocation for BIGNUM !!!!!!!!
{
	NN_DIGIT n[MAX_NN_DIGITS];
	NN_DIGIT p[MAX_NN_DIGITS];
	NN_DIGIT q[MAX_NN_DIGITS];

	NN_DIGIT t[MAX_NN_DIGITS];

	unsigned int nDigits = (pkey->bits + NN_DIGIT_BITS - 1) / NN_DIGIT_BITS;
	unsigned int pDigits = (nDigits + 1) / 2;

	NN_Decode(n, nDigits, pkey->modulus, MAX_RSA_MODULUS_LEN);
	NN_Decode(p, pDigits, pkey->prime[0], MAX_RSA_PRIME_LEN);
	NN_Decode(q, pDigits, pkey->prime[1], MAX_RSA_PRIME_LEN);

	NN_Mult(t, p, q, pDigits);

	if (!NN_Cmp(t, n, nDigits))
		return 0;
	return -1;
}


int eng_rsaref_secret_key_new(IPRIV_KEY_BODY* src,IPRIV_KEY* k)	// dynamic memory allocation for BIGNUM !!!!!!!!
{
	k->key=i_malloc(sizeof(R_RSA_PRIVATE_KEY));
	if(!k->key)
		return CRYPT_ERR_OUT_OF_MEMORY;
	
	R_RSA_PRIVATE_KEY *key = (R_RSA_PRIVATE_KEY *) k->key;
	key->bits = src->bits;
	
	rsaref_mpicpy(src->modulus,sizeof(src->modulus),key->modulus,sizeof(key->modulus));
	rsaref_mpicpy(src->publicExponent,sizeof(src->publicExponent),key->publicExponent,sizeof(key->publicExponent));
	rsaref_mpicpy(src->exponent,sizeof(src->exponent),key->exponent,sizeof(key->exponent));
	rsaref_mpicpy(src->prime1,sizeof(src->prime1),key->prime[1],sizeof(key->prime[1]));
	rsaref_mpicpy(src->prime2,sizeof(src->prime2),key->prime[0],sizeof(key->prime[0]));
	rsaref_mpicpy(src->coefficient,sizeof(src->coefficient),key->coefficient,sizeof(key->coefficient));

	{
		NN_DIGIT d[MAX_NN_DIGITS];
		NN_DIGIT p[MAX_NN_DIGITS];
		NN_DIGIT q[MAX_NN_DIGITS];

		NN_DIGIT dP[MAX_NN_DIGITS];
		NN_DIGIT dQ[MAX_NN_DIGITS];

		NN_DIGIT t[MAX_NN_DIGITS];
		NN_DIGIT pMinus1[MAX_NN_DIGITS];
		NN_DIGIT qMinus1[MAX_NN_DIGITS];

		unsigned int nDigits=(key->bits+NN_DIGIT_BITS-1)/NN_DIGIT_BITS;
		unsigned int pDigits=(nDigits+1)/2;

		NN_Decode(d,nDigits,key->exponent,MAX_RSA_MODULUS_LEN);
		NN_Decode(p,pDigits,key->prime[0],MAX_RSA_PRIME_LEN);
		NN_Decode(q,pDigits,key->prime[1],MAX_RSA_PRIME_LEN);

		NN_ASSIGN_DIGIT(t,1,pDigits);
		NN_Sub(pMinus1,p,t,pDigits);
		NN_Sub(qMinus1,q,t,pDigits);
		NN_Mod(dP,d,nDigits,pMinus1,pDigits);
		NN_Mod(dQ,d,nDigits,qMinus1,pDigits);

		NN_Encode(key->primeExponent[0],MAX_RSA_PRIME_LEN,dP,NN_Digits(dP,pDigits));
		NN_Encode(key->primeExponent[1],MAX_RSA_PRIME_LEN,dQ,NN_Digits(dQ,pDigits));
	}

	if(eng_rsaref_check_secret_key(key))
		return CRYPT_ERR_INVALID_KEY;

		
	return 0;
}

int eng_rsaref_secret_key_delete(IPRIV_KEY *k)
{
	if(k->key)
	{
		memset((char*)k->key,0,sizeof(R_RSA_PRIVATE_KEY));
		i_free(k->key);
		k->key=0;
	}

	return 0;
}


int eng_rsaref_public_key_new(IPRIV_KEY_BODY *src, IPRIV_KEY *k)
{
	k->key=i_malloc(sizeof(R_RSA_PUBLIC_KEY));
	if(!k->key)
		return CRYPT_ERR_OUT_OF_MEMORY;
	
	R_RSA_PUBLIC_KEY *key = (R_RSA_PUBLIC_KEY *) k->key;
	key->bits=src->bits;

	rsaref_mpicpy(src->modulus,sizeof(src->modulus),key->modulus,sizeof(key->modulus));
	rsaref_mpicpy(src->publicExponent,sizeof(src->publicExponent),key->exponent,sizeof(key->exponent));

	return 0;
}

int eng_rsaref_public_key_delete(IPRIV_KEY *k)
{
	if (k->key) {
		memset((char*)k->key, 0, sizeof(R_RSA_PUBLIC_KEY));
		i_free(k->key);
		k->key = 0;
	}

	return 0;
}

int eng_rsaref_ctrl(int cmd,va_list ap)
{
    switch(cmd)
    {
    case IPRIV_ENGCMD_GET_KEY_LENGTH:
	{                                                                                    
	    IPRIV_KEY *k = va_arg(ap,IPRIV_KEY *);
	    if(k && k->key)
		return (k->type==IPRIV_KEY_TYPE_RSA_SECRET)?((R_RSA_PRIVATE_KEY*)k->key)->bits:((R_RSA_PUBLIC_KEY*)k->key)->bits;
	    else
		return CRYPT_ERR_NOT_SUPPORT;
	}
    }
    return CRYPT_ERR_NOT_SUPPORT;
}


int eng_rsaref_secret_key_encrypt(unsigned char *src,int nsrc,unsigned char *dst,int ndst,IPRIV_KEY *k)
{
	R_RSA_PRIVATE_KEY* key=(R_RSA_PRIVATE_KEY*)k->key;
	
	if(!key || k->type!=IPRIV_KEY_TYPE_RSA_SECRET)
		return CRYPT_ERR_INVALID_KEY;

	int n=bits2bytes(key->bits);
	unsigned int nsig=n;
	if(n>ndst)
		return CRYPT_ERR_INVALID_KEYLEN;
	int m=ndst-n;
	int rc=RSAPrivateEncrypt(dst+m,&nsig,src,nsrc,key);
	memset(dst,0,m);

	return (rc || nsig!=n)?CRYPT_ERR_SEC_ENC:0;
}

int eng_rsaref_public_key_decrypt_and_verify(unsigned char* src,int nsrc,unsigned char* dgst,int ndgst,IPRIV_KEY* k)
{
	R_RSA_PUBLIC_KEY* key=(R_RSA_PUBLIC_KEY*)k->key;

	if(!key || k->type!=IPRIV_KEY_TYPE_RSA_PUBLIC)
		return CRYPT_ERR_INVALID_KEY;

	while(ndgst && !(*dgst))
	{
		ndgst--;
		dgst++;
	}
	while(nsrc && !(*src))
	{
		nsrc--;
		src++;
	}
		
	int n=bits2bytes(key->bits);
	MemBuf temp(n);
	if(!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	unsigned int nsig = temp.getlen();
	int rc=RSAPublicDecrypt((unsigned char*)temp.getptr(), &nsig, src, nsrc, key);

	if(rc || nsig!=ndgst)
		return CRYPT_ERR_VERIFY;
	
	if(memcmp(dgst,temp.getptr(),ndgst))
		return CRYPT_ERR_VERIFY;
	return 0;
}


int eng_rsaref_secret_key_export(IPRIV_KEY_BODY* dst,IPRIV_KEY* k)
{
	R_RSA_PRIVATE_KEY* key=(R_RSA_PRIVATE_KEY*)k->key;

	if(!key || k->type!=IPRIV_KEY_TYPE_RSA_SECRET)
		return CRYPT_ERR_INVALID_KEY;

	dst->bits=key->bits;
	
	rsaref_mpicpy(key->modulus,sizeof(key->modulus),dst->modulus,sizeof(dst->modulus));
	rsaref_mpicpy(key->publicExponent,sizeof(key->publicExponent),dst->publicExponent,sizeof(dst->publicExponent));
	rsaref_mpicpy(key->exponent,sizeof(key->exponent),dst->exponent,sizeof(dst->exponent));
	rsaref_mpicpy(key->prime[0],sizeof(key->prime[0]),dst->prime2,sizeof(dst->prime2));
	rsaref_mpicpy(key->prime[1],sizeof(key->prime[1]),dst->prime1,sizeof(dst->prime1));
	rsaref_mpicpy(key->coefficient,sizeof(key->coefficient),dst->coefficient,sizeof(dst->coefficient));

	return 0;
}
int eng_rsaref_public_key_export(IPRIV_KEY_BODY* dst,IPRIV_KEY* k)
{
	R_RSA_PRIVATE_KEY* key=(R_RSA_PRIVATE_KEY*)k->key;

	if(!key || k->type!=IPRIV_KEY_TYPE_RSA_PUBLIC)
		return CRYPT_ERR_INVALID_KEY;

	dst->bits = key->bits;

	rsaref_mpicpy(key->modulus,sizeof(key->modulus),dst->modulus,sizeof(dst->modulus));
	rsaref_mpicpy(key->publicExponent,sizeof(key->publicExponent),dst->publicExponent,sizeof(dst->publicExponent));

	return 0;
}
int eng_rsaref_secret_key_import(IPRIV_KEY_BODY* src)
{
	return CRYPT_ERR_NOT_SUPPORT;
}
int eng_rsaref_public_key_import(IPRIV_KEY_BODY* src)
{
	return CRYPT_ERR_NOT_SUPPORT;
}

#ifdef _WIN32

// MS Windows CryptoAPI key generator code

void eng_rsaref_rmemcpy(BYTE *dst, const BYTE *src, int len)
{
	int i = 0;

	while (len > 0) {
		dst[--len] = src[i++];
	}
}
int eng_rsaref_create_sec_key_data(R_RSA_PRIVATE_KEY * pkey)	// append primeExponent[0], primeExponent[1], coefficient
{
	NN_DIGIT d[MAX_NN_DIGITS];
	NN_DIGIT p[MAX_NN_DIGITS];
	NN_DIGIT q[MAX_NN_DIGITS];

	NN_DIGIT dP[MAX_NN_DIGITS];
	NN_DIGIT dQ[MAX_NN_DIGITS];
	NN_DIGIT qInv[MAX_NN_DIGITS];

	NN_DIGIT t[MAX_NN_DIGITS];
	NN_DIGIT pMinus1[MAX_NN_DIGITS];
	NN_DIGIT qMinus1[MAX_NN_DIGITS];

	unsigned int nDigits = (pkey->bits + NN_DIGIT_BITS - 1) / NN_DIGIT_BITS;
	unsigned int pDigits = (nDigits + 1) / 2;

	NN_Decode(d, nDigits, pkey->exponent, MAX_RSA_MODULUS_LEN);
	NN_Decode(p, pDigits, pkey->prime[0], MAX_RSA_PRIME_LEN);
	NN_Decode(q, pDigits, pkey->prime[1], MAX_RSA_PRIME_LEN);

	/* Sort so that p > q */
	int bSwap = 0;
	if (NN_Cmp (p, q, pDigits) < 0) {
		NN_Assign (t, p, pDigits);
		NN_Assign (p, q, pDigits);
		NN_Assign (q, t, pDigits);
		bSwap = 1;
	}

	NN_ModInv(qInv, q, p, pDigits);
	NN_ASSIGN_DIGIT(t, 1, pDigits);
	NN_Sub(pMinus1, p, t, pDigits);
	NN_Sub(qMinus1, q, t, pDigits);
	NN_Mod(dP, d, nDigits, pMinus1, pDigits);
	NN_Mod(dQ, d, nDigits, qMinus1, pDigits);

	if (bSwap) {
		NN_Encode(pkey->prime[0], MAX_RSA_PRIME_LEN, p, NN_Digits(p, pDigits));
		NN_Encode(pkey->prime[1], MAX_RSA_PRIME_LEN, q, NN_Digits(q, pDigits));
	}
	NN_Encode(pkey->primeExponent[0], MAX_RSA_PRIME_LEN, dP, NN_Digits(dP, pDigits));
	NN_Encode(pkey->primeExponent[1], MAX_RSA_PRIME_LEN, dQ, NN_Digits(dQ, pDigits));
	NN_Encode(pkey->coefficient, MAX_RSA_PRIME_LEN, qInv, NN_Digits(qInv, pDigits));

	return 0;
}
int eng_rsaref_genkey_wincrypt(R_RSA_PRIVATE_KEY* seckey, R_RSA_PUBLIC_KEY* pubkey, int nbits)
{
	HCRYPTPROV hProvider=0;
	HCRYPTKEY hKey;
	DWORD dwBlobLen;
	BYTE *pbKeyBlob;
	DWORD flags=0;
#ifndef _WIN32_WCE
	flags=CRYPT_VERIFYCONTEXT;
#endif
	if (!CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, flags))
		return -1;
	if (!CryptGenKey(hProvider, CALG_RSA_SIGN, nbits<<16 | CRYPT_EXPORTABLE, &hKey))
	{
		CryptReleaseContext(hProvider, 0);
		return -1;
	}
	if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, NULL, &dwBlobLen))
	{
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProvider, 0);
		return -1;
	}
	pbKeyBlob = (BYTE*) i_malloc(dwBlobLen);
	if(!pbKeyBlob)
	{
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProvider, 0);
		return -1;
	}
	if (!CryptExportKey(hKey, NULL, PRIVATEKEYBLOB, 0, pbKeyBlob, &dwBlobLen))
	{
		i_free(pbKeyBlob);
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProvider, 0);
		return -1;
	}

	PUBLICKEYSTRUC *pubstruct;
	RSAPUBKEY *rsakey;
	BYTE *n, *p, *q, *d;


	pubstruct = (PUBLICKEYSTRUC *) pbKeyBlob;
	rsakey = (RSAPUBKEY *) (pbKeyBlob + sizeof(PUBLICKEYSTRUC));
	int byteLen = rsakey->bitlen/8;
	n = ((BYTE *) rsakey) + sizeof(RSAPUBKEY);
	p = n + byteLen;
	q = p + byteLen/2;
	d = q + byteLen*2;

	pubkey->bits = rsakey->bitlen;
	eng_rsaref_rmemcpy(pubkey->modulus+(MAX_RSA_MODULUS_LEN-byteLen), n, byteLen);
	eng_rsaref_rmemcpy(pubkey->exponent+(MAX_RSA_MODULUS_LEN-sizeof(rsakey->pubexp)), (BYTE *) &rsakey->pubexp, sizeof(rsakey->pubexp));

	seckey->bits = rsakey->bitlen;
	eng_rsaref_rmemcpy(seckey->modulus+(MAX_RSA_MODULUS_LEN-byteLen), n, byteLen);
	memcpy(seckey->publicExponent, pubkey->exponent, MAX_RSA_MODULUS_LEN);
	eng_rsaref_rmemcpy(seckey->exponent+(MAX_RSA_MODULUS_LEN-byteLen), d, byteLen);
	eng_rsaref_rmemcpy(seckey->prime[0]+(MAX_RSA_PRIME_LEN-byteLen/2), p, byteLen/2);
	eng_rsaref_rmemcpy(seckey->prime[1]+(MAX_RSA_PRIME_LEN-byteLen/2), q, byteLen/2);

	eng_rsaref_create_sec_key_data(seckey);

	i_free(pbKeyBlob);
	CryptDestroyKey(hKey);
	CryptReleaseContext(hProvider, 0);
	return 0;

}
#endif

int eng_rsaref_genkey(IPRIV_KEY* sec,IPRIV_KEY* pub,int bits)
{
	if(bits<MIN_RSA_MODULUS_BITS || bits>MAX_RSA_MODULUS_BITS)
		return CRYPT_ERR_INVALID_KEYLEN;

	sec->key=i_malloc(sizeof(R_RSA_PRIVATE_KEY));
	if(!sec->key)
		return CRYPT_ERR_OUT_OF_MEMORY;

	pub->key=i_malloc(sizeof(R_RSA_PUBLIC_KEY));
	if(!pub->key)
	{
		i_free(sec->key);
		sec->key=0;
		return CRYPT_ERR_OUT_OF_MEMORY;
	}
	
	R_RSA_PRIVATE_KEY* s=(R_RSA_PRIVATE_KEY*)sec->key;
	R_RSA_PUBLIC_KEY* p=(R_RSA_PUBLIC_KEY*)pub->key;

	memset(s, 0, sizeof(*s));
	memset(p, 0, sizeof(*p));

	int rc;
#if defined(_WIN32) && !defined(WITH_RSAREF_GENKEY)
	rc=eng_rsaref_genkey_wincrypt(s,p,bits);
#else
	R_RSA_PROTO_KEY protoKey;
	protoKey.useFermat4=1;
	protoKey.bits=(unsigned int)bits;
 
	rc=R_GeneratePEMKeys(p,s,&protoKey,&eng_rsaref_random_struct);
#endif
	if(rc)
	{
		i_free(sec->key);
		sec->key=0;
		i_free(pub->key);
		pub->key=0;
		return CRYPT_ERR_GENKEY;
	}
	return 0;
}

#ifdef _WIN32
int eng_rsaref_get_random_seed(unsigned char* dst,int ndst)
{
	HCRYPTPROV hProvider = 0;

	if (!CryptAcquireContext(&hProvider,0,0,PROV_RSA_FULL,CRYPT_VERIFYCONTEXT))
		return 0;
	BOOL rc = CryptGenRandom(hProvider, ndst, dst);
	CryptReleaseContext(hProvider, 0);
	
	return rc ? ndst : 0;
}
#else

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int eng_rsaref_get_random_seed(unsigned char* dst,int ndst)
{
	int fd = open("/dev/random",O_RDONLY);
	if (fd<0) return 0;

	int flags = fcntl(fd, F_GETFL, 0);
	if (flags<0)
	{
		close(fd);
        	return 0;
        }
	if (fcntl(fd,F_SETFL,flags|O_NONBLOCK)<0)
	{
		close(fd);
        	return 0;
        }
	int l = 0;
	while (l<ndst) {
		int n = read(fd,dst+l,ndst-l);
		if (n<=0)
			break;
		l+=n;
	}	
	close(fd);
	return l;
}
#endif

void eng_rsaref_init_random_struct(R_RANDOM_STRUCT* randomStruct)
{
	unsigned char seed[16];
	if(eng_rsaref_get_random_seed(seed,sizeof(seed))!=sizeof(seed))
	{
		uint32 t = (uint32) time(0);
		memcpy(seed,(char*)&t,sizeof(t));
	}

	unsigned int bytesNeeded;
  
	R_RandomInit(randomStruct);

	for(;;)
	{
		R_GetRandomBytesNeeded(&bytesNeeded,randomStruct);
		if(bytesNeeded==0)
			break;
		R_RandomUpdate(randomStruct,seed,sizeof(seed));
	}
}

void eng_rsaref_done_random_struct(R_RANDOM_STRUCT* randomStruct)
{
	R_RandomFinal(randomStruct);
}

int eng_rsaref_gen_random_bytes(unsigned char* dst,int ndst)
{
	if(!R_GenerateBytes(dst,ndst,&eng_rsaref_random_struct))
		return ndst;
	return 0;
}

int eng_rsaref_public_key_encrypt(unsigned char* src,int nsrc,unsigned char* dst,int ndst,IPRIV_KEY* k)
{
	R_RSA_PUBLIC_KEY* key=(R_RSA_PUBLIC_KEY*)k->key;
	
	if(!key || k->type!=IPRIV_KEY_TYPE_RSA_PUBLIC)
		return CRYPT_ERR_INVALID_KEY;

	int n=bits2bytes(key->bits);
	
	if(nsrc>n-11)
		return CRYPT_ERR_INVALID_KEYLEN;
	
	unsigned int nsig=n;
	if(n>ndst)
		return CRYPT_ERR_INVALID_KEYLEN;
	int m=ndst-n;
	int rc=RSAPublicEncrypt(dst+m,&nsig,src,nsrc,key,&eng_rsaref_random_struct);
	
	memset(dst,0,m);

	return (rc || nsig!=n)?CRYPT_ERR_PUB_ENC:0;
}

int eng_rsaref_secret_key_decrypt(unsigned char* src,int nsrc,unsigned char* dst,int ndst,IPRIV_KEY* k)
{
	R_RSA_PRIVATE_KEY* key=(R_RSA_PRIVATE_KEY*)k->key;

	if(!key || k->type!=IPRIV_KEY_TYPE_RSA_SECRET)
		return CRYPT_ERR_INVALID_KEY;

	unsigned int l=ndst;
	int rc=RSAPrivateDecrypt(dst,&l,src,nsrc,key);
	if(rc || !l)
		return CRYPT_ERR_SEC_DEC;

	return l;
}


int eng_rsaref_init(IPRIV_ENGINE* eng)
{
	eng->is_ready=1;
	eng->ctrl=eng_rsaref_ctrl;
	eng->secret_key_new=eng_rsaref_secret_key_new;
	eng->secret_key_delete=eng_rsaref_secret_key_delete;
	eng->public_key_new=eng_rsaref_public_key_new;
	eng->public_key_delete=eng_rsaref_public_key_delete;
	eng->secret_key_encrypt=eng_rsaref_secret_key_encrypt;
	eng->public_key_decrypt_and_verify=eng_rsaref_public_key_decrypt_and_verify;
	eng->secret_key_export=eng_rsaref_secret_key_export;
	eng->public_key_export=eng_rsaref_public_key_export;
	eng->secret_key_import=eng_rsaref_secret_key_import;
	eng->public_key_import=eng_rsaref_public_key_import;
	eng->genkey=eng_rsaref_genkey;
	eng->gen_random_bytes=eng_rsaref_gen_random_bytes;
	eng->public_key_encrypt=eng_rsaref_public_key_encrypt;
	eng->secret_key_decrypt=eng_rsaref_secret_key_decrypt;

	eng_rsaref_init_random_struct(&eng_rsaref_random_struct);


	return 0;
}

int eng_rsaref_done(IPRIV_ENGINE* eng)
{
	eng->is_ready=0;
	eng->ctrl=0;
	eng->secret_key_new=0;
	eng->secret_key_delete=0;
	eng->public_key_new=0;
	eng->public_key_delete=0;
	eng->secret_key_encrypt=0;
	eng->public_key_decrypt_and_verify=0;
	eng->secret_key_export=0;
	eng->public_key_export=0;
	eng->secret_key_import=0;
	eng->public_key_import=0;
	eng->genkey=0;
	eng->gen_random_bytes=0;
	eng->public_key_encrypt=0;
	eng->secret_key_decrypt=0;

	eng_rsaref_done_random_struct(&eng_rsaref_random_struct);

	return 0;
}
