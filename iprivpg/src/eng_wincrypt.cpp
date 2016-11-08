/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com

  engine с ограниченными возможностями.
  export/import не реализован из-за несоответствия способа 
  хранения ключей в Windows (контейнеры) и идеологией libiprivpg
  Для других действий используйте RSAREF

  требует подключения RSAREF

  эффективно использовать только с однократной загрузкой ключей
  и многочисленными вызовами sign/verify

  не ясно, что будет при многозадачности

  eng_wincrypt_public_key_encrypt
  eng_wincrypt_secret_key_decrypt
  работают только начиная с WIndows 2000 + SP??

  проверка подписи портят входной буфер. Другими словами, ее 
  нельзя вызывать несколько раз подряд на одних и тех же данных
*/

#include "eng_wincrypt.h"

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

#include "i_stdlib.h"
#include "i_global.h"
#include "rsaref.h"

#include "packet.h"
#include "eng_rsaref.h"
#include <stdio.h>

#define MAX_LABEL_LENGTH	35

IPRIV_ENGINE *eng_wincrypt_engine_ptr = 0;

typedef struct {
	HCRYPTPROV hProv;
	HCRYPTKEY hKey;
	int byteLen;
	char label[MAX_LABEL_LENGTH];
} WINCRYPT_KEY;


/*
static void dump(unsigned char* src, int nsrc)
{
	for (int i=0; i<nsrc; i++)
		printf("%.2x ",(int) (src[i]));
	printf("\n");
}

static void hexDump(unsigned char* src, int nsrc)
{
	for (int i=0; i<nsrc; i++)
		printf("0x%.2x,",(int) (src[i]));
	printf("\n");
}
*/

// непересекающиеся имена для хранения ключей в контейнере
static int eng_wincrypt_get_key_name(unsigned long keyserial, char *dst, int ndst)
{
	static unsigned long counter = 0;

	return __snprintf(dst, ndst, "cyber-%lu-%lu%u", keyserial, ++counter, GetCurrentThreadId());
}

// копирование задом наперед (массивы не должны пересекаться)
// то есть объединяет memcpy и reverse в одном флаконе
static void eng_wincrypt_rmemcpy(BYTE *dst, const BYTE *src, int len)
{
	int i = 0;

	while (len > 0) {
		dst[--len] = src[i++];
	}
}

// переворот массива на месте
static void eng_wincrypt_reverse(BYTE *mem, int len)
{
	int i = 0;
	BYTE tmp;

	for (i=0; i<len/2; i++) {
		tmp = mem[i];
		mem[i] = mem[len-i-1];
		mem[len-i-1] = tmp;
	}
}

/*
// читабельное сообщение об ошибке в Windows
static void eng_wincrypt_print_error(const char *s)
{
	DWORD dw = GetLastError();
	LPVOID lpMsgBuf;

	FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
		NULL, dw, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR) &lpMsgBuf,0, NULL);
	printf("Windows error %s: %s\n", s, lpMsgBuf);
}
*/

int eng_wincrypt_ctrl(int cmd, va_list ap)
{
	switch(cmd)
	{
        case IPRIV_ENGCMD_GET_KEY_LENGTH:
            return CRYPT_ERR_NOT_SUPPORT;
	}
	return CRYPT_ERR_NOT_SUPPORT;
}

int eng_wincrypt_secret_key_new(IPRIV_KEY_BODY *src, IPRIV_KEY *k)
{
	HCRYPTPROV hProvider = 0;
	HCRYPTKEY hKey;
	DWORD dwBlobLen;
	BYTE *pbKeyBlob;

	char label[MAX_LABEL_LENGTH] = {0};
	eng_wincrypt_get_key_name(src->keyserial, label, sizeof(label)-1);

	int byteLen = bits2bytes(src->bits);
	if (byteLen <= 0)
		return CRYPT_ERR_INVALID_KEY;

	dwBlobLen = sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + byteLen*4 + byteLen/2;
	pbKeyBlob = (BYTE*) i_malloc(dwBlobLen);
	if (!pbKeyBlob) {
		return CRYPT_ERR_OUT_OF_MEMORY;
	}
	memset(pbKeyBlob, 0, dwBlobLen);

	// создать временный RSA_REF ключ для рассчета недостающих парметров RSA ключа
	IPRIV_KEY temp;
	if (eng_rsaref_secret_key_new(src, &temp)) {
		i_free(pbKeyBlob);
		return CRYPT_ERR_INVALID_KEY;
	}

	// работаем с криптопровайдером RSA_FULL
	// удаляем предыдущий и создаем новый контейнер
	CryptAcquireContextA(&hProvider, label, 0, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
	if (!CryptAcquireContextA(&hProvider, label, 0, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		i_free(pbKeyBlob);
		eng_rsaref_secret_key_delete(&temp);
		return CRYPT_ERR_INVALID_KEY;
	}

	// подготовить key BLOB
	PUBLICKEYSTRUC *pubstruct;
	RSAPUBKEY *rsakey;
	BYTE *n, *p, *q, *dmp1, *dmq1, *iqmp, *d;

	pubstruct = (PUBLICKEYSTRUC *) pbKeyBlob;
	rsakey = (RSAPUBKEY *) (pbKeyBlob + sizeof(PUBLICKEYSTRUC));
	n = ((BYTE *) rsakey) + sizeof(RSAPUBKEY);
	p = n + byteLen;
	q = p + byteLen/2;
	dmp1 = q + byteLen/2;
	dmq1 = dmp1 + byteLen/2;
	iqmp = dmq1 + byteLen/2;
	d = iqmp + byteLen/2;

	pubstruct->bType = PRIVATEKEYBLOB;
	pubstruct->bVersion = 0x02;
	pubstruct->reserved = 0;
	pubstruct->aiKeyAlg = CALG_RSA_SIGN | CALG_RSA_KEYX;

	rsakey->magic = 0x32415352;	// "RSA2"
	rsakey->bitlen = byteLen*8;	// получается кратным 8, но, похоже, CryptAPI так и хочет (иначе, rsakey->bitlen = src->bits;)
	eng_wincrypt_rmemcpy((BYTE *) &rsakey->pubexp, src->publicExponent+sizeof(src->publicExponent)-sizeof(rsakey->pubexp), sizeof(rsakey->pubexp));

	eng_wincrypt_rmemcpy(n, src->modulus+sizeof(src->modulus)-byteLen, byteLen);
	eng_wincrypt_rmemcpy(p, src->prime2+sizeof(src->prime2)-byteLen/2, byteLen/2);	// перестановка p и q местами
	eng_wincrypt_rmemcpy(q, src->prime1+sizeof(src->prime1)-byteLen/2, byteLen/2);
	eng_wincrypt_rmemcpy(iqmp, src->coefficient+sizeof(src->coefficient)-byteLen/2, byteLen/2);
	eng_wincrypt_rmemcpy(d, src->exponent+sizeof(src->exponent)-byteLen, byteLen);

	// два числа, рассчитанные RSA_REF
	R_RSA_PRIVATE_KEY* temp_key = (R_RSA_PRIVATE_KEY*) temp.key;
	eng_wincrypt_rmemcpy(dmp1, temp_key->primeExponent[0]+sizeof(temp_key->primeExponent[0])-byteLen/2, byteLen/2);
	eng_wincrypt_rmemcpy(dmq1, temp_key->primeExponent[1]+sizeof(temp_key->primeExponent[1])-byteLen/2, byteLen/2);

	eng_rsaref_secret_key_delete(&temp);	// больше не нужен, удаляем

	// экспортировать в контейнер Windows
	if (!CryptImportKey(hProvider, pbKeyBlob, dwBlobLen, 0, 0, &hKey)) {
		i_free(pbKeyBlob);
		CryptReleaseContext(hProvider, 0);
		return CRYPT_ERR_INVALID_KEY;
	}

//*****************************************
	HCRYPTKEY hKey2;
	pubstruct->aiKeyAlg = CALG_RSA_KEYX; // CALG_RSA_SIGN | CALG_RSA_KEYX;
	CryptImportKey(hProvider, pbKeyBlob, dwBlobLen, 0, 0, &hKey2);
	CryptDestroyKey(hKey2);


	i_free(pbKeyBlob);	// BLOB тоже уже не нужен

	WINCRYPT_KEY *pkey = new WINCRYPT_KEY;
	if (!pkey) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProvider, 0);
		return CRYPT_ERR_OUT_OF_MEMORY;
	}

	// запоолняем хранимые данные
	pkey->hProv = hProvider;
	pkey->hKey = hKey;
	pkey->byteLen = byteLen;
	memcpy(pkey->label, label, sizeof(pkey->label));
	k->key = pkey;
	return 0;
}

int eng_wincrypt_secret_key_delete(IPRIV_KEY *k)
{
	HCRYPTPROV hProvider;

	if (k->key) {
		WINCRYPT_KEY *pkey = (WINCRYPT_KEY *) k->key;
		CryptDestroyKey(pkey->hKey);
		CryptReleaseContext(pkey->hProv, 0);
		CryptAcquireContextA(&hProvider, pkey->label, 0, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		delete pkey;
		k->key = 0;
	}
	return 0;
}

int eng_wincrypt_public_key_new(IPRIV_KEY_BODY *src, IPRIV_KEY *k)
{
	HCRYPTPROV hProvider = 0;
	HCRYPTKEY hKey;
	DWORD dwBlobLen;
	BYTE *pbKeyBlob;

	char label[MAX_LABEL_LENGTH];
	eng_wincrypt_get_key_name(src->keyserial, label, sizeof(label)-1);

	int byteLen = bits2bytes(src->bits);
	if (byteLen <= 0)
		return CRYPT_ERR_INVALID_KEY;

	dwBlobLen = sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY) + byteLen;
	pbKeyBlob = (BYTE*) i_malloc(dwBlobLen);
	if (!pbKeyBlob) {
		return CRYPT_ERR_OUT_OF_MEMORY;
	}
	memset(pbKeyBlob, 0, dwBlobLen);

	// работаем с криптопровайдером RSA_FULL
	CryptAcquireContextA(&hProvider, label, 0, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
	if (!CryptAcquireContextA(&hProvider, label, 0, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
		i_free(pbKeyBlob);
		return CRYPT_ERR_INVALID_KEY;
	}

// подготовить key BLOB
	PUBLICKEYSTRUC *pubstruct;
	RSAPUBKEY *rsakey;
	BYTE *n;

	pubstruct = (PUBLICKEYSTRUC *) pbKeyBlob;
	rsakey = (RSAPUBKEY *) (pbKeyBlob + sizeof(PUBLICKEYSTRUC));
	n = ((BYTE *) rsakey) + sizeof(RSAPUBKEY);

	pubstruct->bType = PUBLICKEYBLOB ;
	pubstruct->bVersion = 0x02;
	pubstruct->reserved = 0;
	pubstruct->aiKeyAlg = CALG_RSA_SIGN | CALG_RSA_KEYX;

	rsakey->magic = 0x31415352;	// "RSA1"
	rsakey->bitlen = byteLen*8;	// получается кратным 8, но, похоже, CryptAPI так и хочет (иначе rsakey->bitlen = src->bits;)
	eng_wincrypt_rmemcpy((BYTE *) &rsakey->pubexp, src->publicExponent+sizeof(src->publicExponent)-sizeof(rsakey->pubexp), sizeof(rsakey->pubexp));

	eng_wincrypt_rmemcpy(n, src->modulus+sizeof(src->modulus)-byteLen, byteLen);

	// экспортировать в контейнер Windows
	if (!CryptImportKey(hProvider, pbKeyBlob, dwBlobLen, 0, 0, &hKey)) {
		i_free(pbKeyBlob);
		CryptReleaseContext(hProvider, 0);
		return CRYPT_ERR_INVALID_KEY;
	}

//*****************************************
	HCRYPTKEY hKey2;
	pubstruct->aiKeyAlg = CALG_RSA_KEYX; // CALG_RSA_SIGN | CALG_RSA_KEYX;
	if (!CryptImportKey(hProvider, pbKeyBlob, dwBlobLen, 0, 0, &hKey2)) {
	}
	CryptDestroyKey(hKey2);

	i_free(pbKeyBlob);

	WINCRYPT_KEY *pkey = new WINCRYPT_KEY;
	if (!pkey) {
		CryptDestroyKey(hKey);
		CryptReleaseContext(hProvider, 0);
		return CRYPT_ERR_OUT_OF_MEMORY;
	}

	// запоолняем хранимые данные
	pkey->hProv = hProvider;
	pkey->hKey = hKey;
	pkey->byteLen = byteLen;
	memcpy(pkey->label, label, sizeof(pkey->label));
	k->key = pkey;
	return 0;
}

int eng_wincrypt_public_key_delete(IPRIV_KEY *k)
{
	HCRYPTPROV hProvider;

	if (k->key) {
		WINCRYPT_KEY *pkey = (WINCRYPT_KEY *) k->key;
		CryptDestroyKey(pkey->hKey);
		CryptReleaseContext(pkey->hProv, 0);
		CryptAcquireContextA(&hProvider, pkey->label, 0, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		delete pkey;
		k->key = 0;
	}
	return 0;
}

int eng_wincrypt_secret_key_encrypt(unsigned char *src, int nsrc, unsigned char *dst, int ndst, IPRIV_KEY *k)
{
	WINCRYPT_KEY *pkey = (WINCRYPT_KEY *) k->key;
	if (!pkey)
		return CRYPT_ERR_INVALID_KEY;

	HCRYPTPROV hProv = pkey->hProv;

	memset(dst, 0, ndst);

	HCRYPTHASH hHash = 0;
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		return CRYPT_ERR_INVALID_KEY;
	}

	if (!CryptSetHashParam(hHash, HP_HASHVAL, src+nsrc-MD5_DIGEST_SIZE, 0)) {	// берем готовый хэш
		CryptDestroyHash(hHash);
		return CRYPT_ERR_INVALID_KEY;
	}

	DWORD sigLen = ndst;
	int rc = CryptSignHash(hHash, AT_KEYEXCHANGE, 0, 0, dst+ndst-pkey->byteLen, &sigLen);	// AT_SIGNATURE AT_KEYEXCHANGE

	CryptDestroyHash(hHash);
	eng_wincrypt_reverse(dst+ndst-pkey->byteLen, sigLen);	// надо перевернуть для OpenSSL

	return !rc ? CRYPT_ERR_SEC_ENC : 0;
}

int eng_wincrypt_public_key_decrypt_and_verify(unsigned char *src, int nsrc, unsigned char *dgst, int ndgst, IPRIV_KEY *k)
{
	int rc;

	WINCRYPT_KEY *pkey = (WINCRYPT_KEY *) k->key;
	if (!pkey)
		return CRYPT_ERR_INVALID_KEY;

	HCRYPTPROV hProv = pkey->hProv;
	HCRYPTKEY hPubKey = pkey->hKey;
	if (!hProv || !hPubKey)
		return CRYPT_ERR_INVALID_KEY;

	while (ndgst && !(*dgst)) {
		ndgst--;
		dgst++;
	}
	while (nsrc && !(*src)) {
		nsrc--;
		src++;
	}

	HCRYPTHASH hHash;
	if (!CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash)) {
		return CRYPT_ERR_INVALID_KEY;
	}

	if (!CryptSetHashParam(hHash, HP_HASHVAL, dgst+ndgst-MD5_DIGEST_SIZE, 0)) {	// берем готовый хэш
		CryptDestroyHash(hHash);
		return CRYPT_ERR_INVALID_KEY;
	}

	eng_wincrypt_reverse(src, nsrc);	// из openssl формата в Windows (портит вход!)
	rc = CryptVerifySignature(hHash, src, nsrc, hPubKey, 0, 0);

	CryptDestroyHash(hHash);
	return !rc ? CRYPT_ERR_VERIFY : 0;
}

// следующие две функции нужны для записи вновь созданных ключей
int eng_wincrypt_secret_key_export(IPRIV_KEY_BODY *dst, IPRIV_KEY *k)
{
	return CRYPT_ERR_NOT_SUPPORT;
}

int eng_wincrypt_public_key_export(IPRIV_KEY_BODY *dst, IPRIV_KEY *k)
{
	return CRYPT_ERR_NOT_SUPPORT;
}

int eng_wincrypt_secret_key_import(IPRIV_KEY_BODY *src)
{
	return CRYPT_ERR_NOT_SUPPORT;
}

int eng_wincrypt_public_key_import(IPRIV_KEY_BODY *src)
{
	return CRYPT_ERR_NOT_SUPPORT;
}

int eng_wincrypt_genkey(IPRIV_KEY *sec, IPRIV_KEY *pub, int bits)
{
	return CRYPT_ERR_NOT_SUPPORT;
}

int eng_wincrypt_gen_random_bytes(unsigned char *dst, int ndst)
{
	HCRYPTPROV hProv = 0;

	if (!CryptAcquireContext(&hProv, 0, 0, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT))
		return 0;
	BOOL rc = CryptGenRandom(hProv, ndst, dst);
	CryptReleaseContext(hProv, 0);
	
	return rc ? ndst : 0;
}

int eng_wincrypt_public_key_encrypt(unsigned char *src, int nsrc, unsigned char *dst, int ndst, IPRIV_KEY *k)
{

	WINCRYPT_KEY *pkey = (WINCRYPT_KEY *) k->key;
	if (!pkey)
		return CRYPT_ERR_INVALID_KEY;

	HCRYPTPROV hProv = pkey->hProv;
	HCRYPTKEY hKey = pkey->hKey;
	if (!hProv || !hKey)
		return CRYPT_ERR_INVALID_KEY;

	if (ndst < pkey->byteLen || nsrc > pkey->byteLen-11)
		return CRYPT_ERR_INVALID_KEYLEN;
	
	memset(dst, 0, ndst);
	BYTE *buf = (BYTE*) i_malloc(pkey->byteLen);
	memcpy(buf, src, nsrc);
	DWORD len = nsrc;

	int rc = CryptEncrypt(hKey, 0, TRUE, 0, buf, &len, pkey->byteLen);
	if (rc) {
		memcpy(dst, buf, len);
		eng_wincrypt_reverse(dst, ndst);
	}
	i_free(buf);

	return rc ? 0 : CRYPT_ERR_PUB_ENC;
}

int eng_wincrypt_secret_key_decrypt(unsigned char *src, int nsrc, unsigned char *dst, int ndst, IPRIV_KEY *k)
{
	WINCRYPT_KEY *pkey = (WINCRYPT_KEY *) k->key;
	if (!pkey)
		return CRYPT_ERR_INVALID_KEY;

	HCRYPTPROV hProv = pkey->hProv;
	HCRYPTKEY hKey = pkey->hKey;
	if (!hProv || !hKey)
		return CRYPT_ERR_INVALID_KEY;

	memset(dst, 0, ndst);
	BYTE *buf = (BYTE*) i_malloc(nsrc);
	memcpy(buf, src, nsrc);
	eng_wincrypt_reverse(buf, nsrc);
	DWORD len = nsrc;

	int rc = CryptDecrypt(hKey, 0, TRUE, 0, buf, &len);
	if (rc)
		memcpy(dst, buf, len);
	i_free(buf);

	return rc ? len : CRYPT_ERR_SEC_DEC;
}


int eng_wincrypt_init(IPRIV_ENGINE* eng)
{
	eng_wincrypt_engine_ptr = eng;

	eng->ctrl = eng_wincrypt_ctrl;
	eng->secret_key_new = eng_wincrypt_secret_key_new;
	eng->secret_key_delete = eng_wincrypt_secret_key_delete;
	eng->public_key_new = eng_wincrypt_public_key_new;
	eng->public_key_delete = eng_wincrypt_public_key_delete;
	eng->secret_key_encrypt = eng_wincrypt_secret_key_encrypt;
	eng->public_key_decrypt_and_verify = eng_wincrypt_public_key_decrypt_and_verify;
	eng->secret_key_export = eng_wincrypt_secret_key_export;
	eng->public_key_export = eng_wincrypt_public_key_export;
	eng->secret_key_import = eng_wincrypt_secret_key_import;
	eng->public_key_import = eng_wincrypt_public_key_import;
	eng->genkey = eng_wincrypt_genkey;
	eng->gen_random_bytes = eng_wincrypt_gen_random_bytes;
	eng->public_key_encrypt = eng_wincrypt_public_key_encrypt;
	eng->secret_key_decrypt = eng_wincrypt_secret_key_decrypt;

	eng->is_ready = 1;
	return 0;
}

int eng_wincrypt_done(IPRIV_ENGINE* eng)
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

	eng_wincrypt_engine_ptr = 0;
	return 0;
}

#else

int eng_wincrypt_init(IPRIV_ENGINE* eng)
{
	eng->is_ready = 0;
	return 0;
}

int eng_wincrypt_done(IPRIV_ENGINE* eng)
{
	return 0;
}

#endif /* _WIN32 */
