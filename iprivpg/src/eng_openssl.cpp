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
#else
#include <string.h>
#include <unistd.h>
#endif /* _WIN32 */

#include <openssl/ssl.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include "eng_openssl.h"
#include "packet.h"


/*
static void dump(unsigned char* src, int nsrc)
{
	for (int i=0; i<nsrc; i++)
		printf("%.2x ",(int) (src[i]));
	printf("\n");
}
*/

static void convertNumber(unsigned char *in, int size, BIGNUM *out)
{
	int nbits = Packet::calc_bit_count(in, size);
	int n = bits2bytes(nbits);

	BN_bin2bn(in+size-n, n, out);

}

static void convertNumber2(BIGNUM *in, unsigned char *out, int size)
{
	int n = BN_num_bytes(in);

	memset(out, 0, size);
	BN_bn2bin(in, out+size-n);
}

// если в системе есть /dev/urandom, то используется автоматически
static void seedPRNG()
{
#ifdef _WIN32
	char reqid[sizeof(DWORD)+sizeof(DWORD)+sizeof(WORD)];
	*((DWORD*)reqid) = (time(0));
	*((DWORD*)(reqid+sizeof(DWORD))) = (GetCurrentThreadId());
	*((WORD*)(reqid+sizeof(DWORD)+sizeof(DWORD))) = (WORD) rand();
#else
	char reqid[sizeof(time_t) + sizeof(pid_t) + sizeof(int)];
	*((time_t*) reqid) = (time(0));
	*((pid_t*)(reqid + sizeof(time_t))) = (getpid());
	*((int *)(reqid + sizeof(time_t) + sizeof(pid_t))) = (rand());
#endif

	RAND_seed(reqid, sizeof(reqid));
}

// если не задать, то будет спрашивать с терминала
static int def_pass_cb(char *buf, int size, int rwflag, void *u)
{
	*buf = 0;
	return 0;
}

// экспорт в PEM формат открытых и закрытых ключей
static int eng_openssl_pem_export(IPRIV_KEY *k, const char *phrase, char *dst, int ndst)
{
	if (!k || !k->key || k->eng!=IPRIV_ENGINE_OPENSSL || !dst || ndst<=0)
		return CRYPT_ERR_INVALID_KEY;

	long len;
	int rc = CRYPT_ERR_INVALID_KEY;
	RSA *rsa = (RSA *) k->key;
	BIO *bio_out = BIO_new(BIO_s_mem());

	if (!bio_out)
		return CRYPT_ERR_OUT_OF_MEMORY;

	if (k->type == IPRIV_KEY_TYPE_RSA_PUBLIC) {
//		if (PEM_write_bio_RSAPublicKey(bio_out, rsa))	// PKCS#1 RSAPublicKey (2 числа)
		if (PEM_write_bio_RSA_PUBKEY(bio_out, rsa))	// другой формат откр. ключа (SubjectPublicKeyInfo)
			rc = 0;
	} else if (k->type == IPRIV_KEY_TYPE_RSA_SECRET) {
		if (phrase && *phrase) {	// с шифрованием кодовой фразой алгоритмом DES3
			if (PEM_write_bio_RSAPrivateKey(bio_out, rsa, EVP_des_ede3_cbc(), 0, 0, 0, (void *) phrase))
				rc = 0;
		} else {	// без шифрования
			if (PEM_write_bio_RSAPrivateKey(bio_out, rsa, 0, 0, 0, 0, 0))
				rc = 0;
		}
	}

	if (!rc) {
		char *s;
		len = BIO_get_mem_data(bio_out, &s);
		if (len < ndst) {
			memcpy(dst, s, len);
			dst[len] = 0;
		} else
			rc = CRYPT_ERR_OUT_OF_MEMORY;
	}

	BIO_free(bio_out);
	return rc;
}

// импорт из PEM ключей
static int eng_openssl_pem_import(IPRIV_KEY *k, const char *phrase, char *src, int nsrc)
{
	if (!k || k->eng!=IPRIV_ENGINE_OPENSSL || !src)
		return CRYPT_ERR_INVALID_KEY;

	int rc = CRYPT_ERR_INVALID_KEY;
	RSA *rsa = 0;
	BIO *bio = BIO_new_mem_buf(src, nsrc<=0 ? -1 : nsrc);

	if (!bio)
		return CRYPT_ERR_OUT_OF_MEMORY;

	if (k->type == IPRIV_KEY_TYPE_RSA_PUBLIC) {
		rsa = PEM_read_bio_RSAPublicKey(bio, 0, 0, (void *) ((phrase && *phrase) ? phrase : 0));
	} else if (k->type == IPRIV_KEY_TYPE_RSA_SECRET) {
		rsa = PEM_read_bio_RSAPrivateKey(bio, 0, (phrase && *phrase) ? 0 : def_pass_cb, (void *) ((phrase && *phrase) ? phrase : 0));
	}

	if (rsa) {
		k->key = rsa;
		rc = 0;
	}

	BIO_free(bio);
	return rc;
}


IPRIV_ENGINE *eng_openssl_engine_ptr = 0;

int eng_openssl_ctrl(int cmd, va_list ap)
{
	IPRIV_KEY *k;
	const char *phrase;
	char *dst, *src;
	int ndst, nsrc;

	switch (cmd) {
	case IPRIV_ENGCMD_PEM_EXPORT:
		k = va_arg(ap, IPRIV_KEY *);
		phrase = va_arg(ap, const char *);
		dst = va_arg(ap, char *);
		ndst = va_arg(ap, int);
		return eng_openssl_pem_export(k, phrase, dst, ndst);

	case IPRIV_ENGCMD_PEM_IMPORT:
		k = va_arg(ap, IPRIV_KEY *);
		phrase = va_arg(ap, const char *);
		src = va_arg(ap, char *);
		nsrc = va_arg(ap, int);
		return eng_openssl_pem_import(k, phrase, src, nsrc);

        case IPRIV_ENGCMD_GET_KEY_LENGTH:
		k = va_arg(ap, IPRIV_KEY *);
	
		if(k && k->key)
		{
	    	    RSA *rsa = (RSA *) k->key;
		    if (rsa)
			return BN_num_bits(rsa->n);
		}
                return CRYPT_ERR_NOT_SUPPORT;

	default:
		return CRYPT_ERR_NOT_SUPPORT;
	}

	return 0;
}

int eng_openssl_secret_key_new(IPRIV_KEY_BODY *src, IPRIV_KEY *k)
{
	RSA *rsa;
	BN_CTX *ctx;
	BIGNUM *r1, *r2;

	rsa = RSA_new();
	if (!rsa)
		return CRYPT_ERR_OUT_OF_MEMORY;

	rsa->n = BN_new();
	rsa->e = BN_new();
	rsa->d = BN_new();
	rsa->p = BN_new();
	rsa->q = BN_new();
	rsa->dmp1 = BN_new();
	rsa->dmq1 = BN_new();
	rsa->iqmp = BN_new();
	if (!rsa->n || !rsa->e || !rsa->d || !rsa->p || !rsa->q || !rsa->dmp1 || !rsa->dmq1 || !rsa->iqmp) {
		RSA_free(rsa);
		return CRYPT_ERR_OUT_OF_MEMORY;
	}

	convertNumber(src->modulus, sizeof(src->modulus), rsa->n);
	convertNumber(src->publicExponent, sizeof(src->publicExponent), rsa->e);
	convertNumber(src->exponent, sizeof(src->exponent), rsa->d);
	convertNumber(src->prime1, sizeof(src->prime1), rsa->q);	// перестановка !!
	convertNumber(src->prime2, sizeof(src->prime2), rsa->p);
	convertNumber(src->coefficient, sizeof(src->coefficient), rsa->iqmp);

	ctx = BN_CTX_new();
	if (!ctx) {
		RSA_free(rsa);
		return CRYPT_ERR_OUT_OF_MEMORY;
	}
	BN_CTX_start(ctx);
	r1 = BN_CTX_get(ctx);
	r2 = BN_CTX_get(ctx);

	//подсчитать два дополнительных числа для ускорения процесса шифрования
	BN_sub(r1, rsa->p, BN_value_one());
	BN_sub(r2, rsa->q, BN_value_one());
	BN_mod(rsa->dmp1, rsa->d, r1, ctx);
	BN_mod(rsa->dmq1, rsa->d, r2, ctx);

	BN_CTX_end(ctx);
	BN_CTX_free(ctx);

	if (!RSA_check_key(rsa)) {
		RSA_free(rsa);
		return CRYPT_ERR_INVALID_KEY;
	} else {
		k->key = rsa;
		return 0;
	}
}

int eng_openssl_secret_key_delete(IPRIV_KEY *k)
{
	if (k->key) {
		RSA_free((RSA *) k->key);
		k->key = 0;
	}

	return 0;
}

int eng_openssl_public_key_new(IPRIV_KEY_BODY *src, IPRIV_KEY *k)
{
	RSA *rsa;

	rsa = RSA_new();
	if (!rsa)
		return CRYPT_ERR_OUT_OF_MEMORY;

	rsa->n = BN_new();
	rsa->e = BN_new();

	convertNumber(src->modulus, sizeof(src->modulus), rsa->n);
	convertNumber(src->publicExponent, sizeof(src->publicExponent), rsa->e);

	k->key = rsa;
	return 0;
}

int eng_openssl_public_key_delete(IPRIV_KEY *k)
{
	if (k->key) {
		RSA_free((RSA *) k->key);
		k->key = 0;
	}

	return 0;
}

int eng_openssl_secret_key_encrypt(unsigned char *src, int nsrc, unsigned char *dst, int ndst, IPRIV_KEY *k)
{
	RSA *rsa = (RSA *) k->key;
	if (!rsa || k->type!=IPRIV_KEY_TYPE_RSA_SECRET)
		return CRYPT_ERR_INVALID_KEY;

	int n = RSA_size(rsa);
	if (ndst < n)
		return CRYPT_ERR_INVALID_KEYLEN;

	memset(dst, 0, ndst);
	int rc = RSA_private_encrypt(nsrc, src, dst+ndst-n, rsa, RSA_PKCS1_PADDING);

	return rc<0 ? CRYPT_ERR_SEC_ENC : 0;
}

int eng_openssl_public_key_decrypt_and_verify(unsigned char *src, int nsrc, unsigned char *dgst, int ndgst, IPRIV_KEY *k)
{
	RSA *rsa = (RSA *) k->key;
	if (!rsa || k->type!=IPRIV_KEY_TYPE_RSA_PUBLIC)
		return CRYPT_ERR_INVALID_KEY;

	while(ndgst && !(*dgst)) {
		ndgst--;
		dgst++;
	}
	while(nsrc && !(*src)) {
		nsrc--;
		src++;
	}

	int n = RSA_size(rsa);
	MemBuf temp(n);
	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	int rc = RSA_public_decrypt(nsrc, src, (unsigned char*) temp.getptr(), rsa, RSA_PKCS1_PADDING);

	if (rc != ndgst)
		return CRYPT_ERR_VERIFY;

	if (memcmp(dgst, temp.getptr(), ndgst))
		return CRYPT_ERR_VERIFY;
	else
		return 0;
}

int eng_openssl_secret_key_export(IPRIV_KEY_BODY *dst, IPRIV_KEY *k)
{
	RSA *rsa = (RSA *) k->key;
	if (!rsa || !dst|| k->type!=IPRIV_KEY_TYPE_RSA_SECRET)
		return CRYPT_ERR_INVALID_KEY;

	dst->bits = BN_num_bits(rsa->n);

	convertNumber2(rsa->n, dst->modulus, sizeof(dst->modulus));
	convertNumber2(rsa->e, dst->publicExponent, sizeof(dst->publicExponent));
	convertNumber2(rsa->d, dst->exponent, sizeof(dst->exponent));
	convertNumber2(rsa->q, dst->prime1, sizeof(dst->prime1));	// обратная перестановка !!
	convertNumber2(rsa->p, dst->prime2, sizeof(dst->prime2));
	convertNumber2(rsa->iqmp, dst->coefficient, sizeof(dst->coefficient));
//	mp_inv(pKey->u, pKey->p, pKey->q);			/* (p*u) mod q = 1, assuming p<q */

	return 0;
}

int eng_openssl_public_key_export(IPRIV_KEY_BODY *dst, IPRIV_KEY *k)
{
	RSA *rsa = (RSA *) k->key;
	if (!rsa || k->type!=IPRIV_KEY_TYPE_RSA_PUBLIC)
		return CRYPT_ERR_INVALID_KEY;

	dst->bits = BN_num_bits(rsa->n);

	convertNumber2(rsa->n, dst->modulus, sizeof(dst->modulus));
	convertNumber2(rsa->e, dst->publicExponent, sizeof(dst->publicExponent));

	return 0;
}

int eng_openssl_secret_key_import(IPRIV_KEY_BODY *src)
{
	return CRYPT_ERR_NOT_SUPPORT;
}

int eng_openssl_public_key_import(IPRIV_KEY_BODY *src)
{
	return CRYPT_ERR_NOT_SUPPORT;
}

int eng_openssl_genkey(IPRIV_KEY *sec, IPRIV_KEY *pub, int bits)
{
	if (!sec || !pub || !bits)
		return CRYPT_ERR_INVALID_KEYLEN;

	sec->key = RSA_generate_key(bits, 0x10001, 0, 0);
	if (!sec->key)
		return CRYPT_ERR_GENKEY;

	RSA *rsa = RSA_new();
	if (!rsa) {
		RSA_free((RSA *) sec->key);
		sec->key = 0;
		return CRYPT_ERR_OUT_OF_MEMORY;
	}

	rsa->n = BN_new();
	rsa->e = BN_new();
	if (!rsa->n || !rsa->e) {
		RSA_free((RSA *) sec->key);
		sec->key = 0;
		RSA_free(rsa);
		return CRYPT_ERR_OUT_OF_MEMORY;
	}
	BN_copy(rsa->n, ((RSA *) sec->key)->n);
	BN_copy(rsa->e, ((RSA *) sec->key)->e);
	pub->key = rsa;

	return 0;
}

int eng_openssl_gen_random_bytes(unsigned char *dst, int ndst)
{
	if (RAND_pseudo_bytes(dst, ndst)>=0)	// или >=0, если разрешить не криптографически сильные rnd
		return ndst;
	else
		return 0;
}

int eng_openssl_public_key_encrypt(unsigned char *src, int nsrc, unsigned char *dst, int ndst, IPRIV_KEY *k)
{
	RSA *rsa = (RSA *) k->key;
	if (!rsa || k->type!=IPRIV_KEY_TYPE_RSA_PUBLIC)
		return CRYPT_ERR_INVALID_KEY;

	int n = RSA_size(rsa);
	if (ndst < n || nsrc > n-11)
		return CRYPT_ERR_INVALID_KEYLEN;
	
	memset(dst, 0, ndst);
	int rc = RSA_public_encrypt(nsrc, src, dst+ndst-n, rsa, RSA_PKCS1_PADDING);

	return rc<0 ? CRYPT_ERR_PUB_ENC : 0;
}

int eng_openssl_secret_key_decrypt(unsigned char *src, int nsrc, unsigned char *dst, int ndst, IPRIV_KEY *k)
{
	RSA *rsa = (RSA *) k->key;
	if (!rsa || k->type!=IPRIV_KEY_TYPE_RSA_SECRET)
		return CRYPT_ERR_INVALID_KEY;

	int rc = RSA_private_decrypt(nsrc, src, dst, rsa, RSA_PKCS1_PADDING);

	return rc<0 ? CRYPT_ERR_SEC_DEC : rc;
}

int eng_openssl_init(IPRIV_ENGINE *eng)
{
	eng_openssl_engine_ptr =eng;

	ERR_load_crypto_strings();
//	SSL_library_init();
	seedPRNG();

	eng->ctrl = eng_openssl_ctrl;
	eng->secret_key_new = eng_openssl_secret_key_new;
	eng->secret_key_delete = eng_openssl_secret_key_delete;
	eng->public_key_new = eng_openssl_public_key_new;
	eng->public_key_delete = eng_openssl_public_key_delete;
	eng->secret_key_encrypt = eng_openssl_secret_key_encrypt;
	eng->public_key_decrypt_and_verify = eng_openssl_public_key_decrypt_and_verify;
	eng->secret_key_export = eng_openssl_secret_key_export;
	eng->public_key_export = eng_openssl_public_key_export;
	eng->secret_key_import = eng_openssl_secret_key_import;
	eng->public_key_import = eng_openssl_public_key_import;
	eng->genkey = eng_openssl_genkey;
	eng->gen_random_bytes = eng_openssl_gen_random_bytes;
	eng->public_key_encrypt = eng_openssl_public_key_encrypt;
	eng->secret_key_decrypt = eng_openssl_secret_key_decrypt;

	eng->is_ready = 1;
	return 0;
}

int eng_openssl_done(IPRIV_ENGINE *eng)
{
	eng->is_ready = 0;

	eng->ctrl = 0;
	eng->secret_key_new = 0;
	eng->secret_key_delete = 0;
	eng->public_key_new = 0;
	eng->public_key_delete = 0;
	eng->secret_key_encrypt = 0;
	eng->public_key_decrypt_and_verify = 0;
	eng->secret_key_export = 0;
	eng->public_key_export = 0;
	eng->secret_key_import = 0;
	eng->public_key_import = 0;
	eng->genkey = 0;
	eng->gen_random_bytes = 0;
	eng->public_key_encrypt = 0;
	eng->secret_key_decrypt = 0;

	ERR_free_strings();

	eng_openssl_engine_ptr = 0;
	return 0;
}
