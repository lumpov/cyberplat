/*
   Copyright (C) 1998-2010 CyberPlat. All Rights Reserved.
   e-mail: support@cyberplat.com
*/

#ifdef _WIN32
#include <windows.h>
#endif

#include "libipriv.h"
#include "ipriv.h"
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include "i_stdlib.h"
#include "armor.h"
#include "packet.h"
#include <time.h>
#include "keycard.h"
#include "radix64.h"

#ifdef WITH_RSAREF
#include "eng_rsaref.h"
#endif

#ifdef WITH_OPENSSL
#include "eng_openssl.h"
#endif

#ifdef WITH_PKCS11
#include "eng_pkcs11.h"
#endif

#ifdef WITH_PKCS11_RUTOKEN
#include "eng_pkcs11_rutoken.h"
#endif

#ifdef WITH_WINCRYPT
#include "eng_wincrypt.h"
#endif

#ifdef WITH_SENSELOCK
#include "eng_senselock.h"
#endif


IPRIV_ENGINE crypt_eng_list[IPRIV_MAX_ENG_NUM];


int IPRIVAPI Crypt_Initialize(void)
{
	memset((char *) crypt_eng_list, 0, sizeof(crypt_eng_list));
	CryptInitCRC();

#ifdef WITH_RSAREF
	crypt_eng_list[IPRIV_ENGINE_RSAREF].type = IPRIV_ENGINE_RSAREF;
	eng_rsaref_init(crypt_eng_list + IPRIV_ENGINE_RSAREF);
#endif

#ifdef WITH_OPENSSL
	crypt_eng_list[IPRIV_ENGINE_OPENSSL].type = IPRIV_ENGINE_OPENSSL;
	eng_openssl_init(crypt_eng_list + IPRIV_ENGINE_OPENSSL);
#endif

#ifdef WITH_PKCS11
	crypt_eng_list[IPRIV_ENGINE_PKCS11].type = IPRIV_ENGINE_PKCS11;
	eng_pkcs11_init(crypt_eng_list + IPRIV_ENGINE_PKCS11);
#endif

#ifdef WITH_PKCS11_RUTOKEN
	crypt_eng_list[IPRIV_ENGINE_PKCS11_RUTOKEN].type = IPRIV_ENGINE_PKCS11_RUTOKEN;
	eng_pkcs11_rutoken_init(crypt_eng_list + IPRIV_ENGINE_PKCS11_RUTOKEN);
#endif

#ifdef WITH_WINCRYPT
	crypt_eng_list[IPRIV_ENGINE_WINCRYPT].type = IPRIV_ENGINE_WINCRYPT;
	eng_wincrypt_init(crypt_eng_list + IPRIV_ENGINE_WINCRYPT);
#endif

#ifdef WITH_SENSELOCK
	crypt_eng_list[IPRIV_ENGINE_SENSELOCK].type = IPRIV_ENGINE_SENSELOCK;
	eng_senselock_init(crypt_eng_list + IPRIV_ENGINE_SENSELOCK);
#endif

	return 0;
}

int IPRIVAPI Crypt_Done(void)
{
#ifdef WITH_RSAREF
	eng_rsaref_done(crypt_eng_list + IPRIV_ENGINE_RSAREF);
#endif

#ifdef WITH_OPENSSL
	eng_openssl_done(crypt_eng_list + IPRIV_ENGINE_OPENSSL);
#endif

#ifdef WITH_PKCS11
	eng_pkcs11_done(crypt_eng_list + IPRIV_ENGINE_PKCS11);
#endif

#ifdef WITH_PKCS11_RUTOKEN
	eng_pkcs11_rutoken_done(crypt_eng_list + IPRIV_ENGINE_PKCS11_RUTOKEN);
#endif

#ifdef WITH_WINCRYPT
	eng_wincrypt_done(crypt_eng_list + IPRIV_ENGINE_WINCRYPT);
#endif

	memset((char *) crypt_eng_list, 0, sizeof(crypt_eng_list));
	return 0;
}


int Crypt_Ctrl(int eng, int cmd, ...)
{
	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;

	switch (cmd) {
	case IPRIV_ENGCMD_IS_READY:
		return crypt_eng_list[eng].is_ready ? 1 : 0;
	case IPRIV_ENGCMD_GET_ERROR:
		return crypt_eng_list[eng].error;
	}

	if (!crypt_eng_list[eng].ctrl)
		return CRYPT_ERR_NOT_SUPPORT;

	va_list ap;

	va_start(ap, cmd);
	int rc = crypt_eng_list[eng].ctrl(cmd, ap);

	va_end(ap);
	return rc;
}

int IPRIVAPI Crypt_Ctrl_Null(int eng, int cmd)
{
	return Crypt_Ctrl(eng, cmd);
}

int IPRIVAPI Crypt_Ctrl_String(int eng, int cmd, const char *arg)
{
	return Crypt_Ctrl(eng, cmd, arg);
}

int IPRIVAPI Crypt_Ctrl_Int(int eng, int cmd, int arg)
{
	return Crypt_Ctrl(eng, cmd, arg);
}

int IPRIVAPI Crypt_Ctrl_Ptr(int eng, int cmd, void *arg)
{
	return Crypt_Ctrl(eng, cmd, arg);
}

#include "secure.h"

int Crypt_OpenSecretKey_Internal(int eng, const char *src, int nsrc, const char *passwd, IPRIV_KEY *key, int imp)
{
	if (key)
		memset((char *) key, 0, sizeof(*key));

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (imp) {
		if (!crypt_eng_list[eng].secret_key_import)
			return CRYPT_ERR_NOT_SUPPORT;
	} else {
		if (!crypt_eng_list[eng].secret_key_new)
			return CRYPT_ERR_NOT_SUPPORT;
	}

	IPRIV_KEY_BODY k;

	memset((char *) &k, 0, sizeof(k));

	int rc = Crypt_ReadSecretKey(src, nsrc, passwd, &k);

	if (rc < 0)
		return rc;

	if (imp)
		rc = crypt_eng_list[eng].secret_key_import(&k);
	else {
		key->keyserial = k.keyserial;
		strcpy(key->userid, k.userid);
		key->eng = eng;
		key->type = IPRIV_KEY_TYPE_RSA_SECRET;

		rc = crypt_eng_list[eng].secret_key_new(&k, key);
	}

	memset((char *) &k, 0, sizeof(k));

	return rc;
}

int IPRIVAPI Crypt_OpenSecretKey(int eng, const char *src, int nsrc, const char *passwd, IPRIV_KEY *key)
{
	return Crypt_OpenSecretKey_Internal(eng, src, nsrc, passwd, key, 0);
}

int IPRIVAPI Crypt_OpenSecretKey2(int eng, const char *src, int nsrc, const char *passwd, IPRIV_KEY *key)
{
	if (key)
		memset((char *) key, 0, sizeof(*key));

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].secret_key_new)
		return CRYPT_ERR_NOT_SUPPORT;

	IPRIV_KEY_BODY k;

	memset((char *) &k, 0, sizeof(k));

	int rc = Crypt_ReadSecretKey2(src, nsrc, passwd, &k);

	if (rc < 0)
		return rc;

	key->keyserial = k.keyserial;
	strcpy(key->userid, k.userid);
	key->eng = eng;
	key->type = IPRIV_KEY_TYPE_RSA_SECRET;

	rc = crypt_eng_list[eng].secret_key_new(&k, key);

	memset((char *) &k, 0, sizeof(k));

	return rc;
}

int Crypt_OpenSecretKeyFromFile_Internal(int eng, const char *path, const char *passwd, IPRIV_KEY *key, int imp)
{
	if (key)
		memset((char *) key, 0, sizeof(*key));

	MemBuf temp(4096);

	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;
	FILE *fp = fopen(path, "rb");

	if (!fp)
		return CRYPT_ERR_FILE_NOT_FOUND;
	int rc = fread(temp.getptr(), 1, temp.getlen(), fp);

	fclose(fp);
	if (!rc)
		return CRYPT_ERR_CANT_READ_FILE;
	return Crypt_OpenSecretKey_Internal(eng, temp.getptr(), rc, passwd, key, imp);
}

int IPRIVAPI Crypt_OpenSecretKeyFromFile(int eng, const char *path, const char *passwd, IPRIV_KEY *key)
{
	return Crypt_OpenSecretKeyFromFile_Internal(eng, path, passwd, key, 0);
}

int IPRIVAPI Crypt_OpenSecretKeyFromStore(int eng, unsigned long keyserial, IPRIV_KEY *key)
{
	memset((char *) key, 0, sizeof(*key));

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].secret_key_new)
		return CRYPT_ERR_NOT_SUPPORT;

	IPRIV_KEY_BODY k;

	memset((char *) &k, 0, sizeof(k));
	k.keyserial = keyserial;
	key->keyserial = k.keyserial;
	key->eng = eng;
	key->type = IPRIV_KEY_TYPE_RSA_SECRET;

	int rc = crypt_eng_list[eng].secret_key_new(&k, key);

	memset((char *) &k, 0, sizeof(k));

	return rc;
}

int IPRIVAPI Crypt_CloseKey(IPRIV_KEY *key)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	int rc = CRYPT_ERR_INVALID_KEY;

	if (key->type == IPRIV_KEY_TYPE_RSA_SECRET) {
		if (!crypt_eng_list[eng].secret_key_delete)
			return CRYPT_ERR_NOT_SUPPORT;
		rc = crypt_eng_list[eng].secret_key_delete(key);
	} else if (key->type == IPRIV_KEY_TYPE_RSA_PUBLIC) {
		if (!crypt_eng_list[eng].public_key_delete)
			return CRYPT_ERR_NOT_SUPPORT;
		rc = crypt_eng_list[eng].public_key_delete(key);
	}
	memset((char *) key, 0, sizeof(*key));

	return rc;
}

static int __ipriv_hash_alg=IPRIV_ALG_MD5;

int IPRIVAPI Crypt_SetHashAlg(int alg)
{
    if(alg!=IPRIV_ALG_MD5 && alg!=IPRIV_ALG_SHA256)
        return CRYPT_ERR_UNKNOWN_ALG;

    __ipriv_hash_alg=alg;

    return 0;
}

int IPRIVAPI Crypt_Sign(const char *src, int nsrc, char *dst, int ndst, IPRIV_KEY *key)
{
    return Crypt_SignEx(src,nsrc,dst,ndst,key,__ipriv_hash_alg);
}

int IPRIVAPI Crypt_SignEx(const char *src, int nsrc, char *dst, int ndst, IPRIV_KEY *key, int alg)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (nsrc < 0)
		nsrc = strlen(src);

	MemBuf temp(nsrc + 2048);	// 4096

	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;
	int rc = Crypt_SignPacket(src, nsrc, key, temp.getptr(), temp.getlen(), 0, 0, crypt_eng_list + eng, alg);

	if (rc <= 0)
		return rc;

	doc_info di;

	di.version = 1;
	strcpy(di.type, "SM");
	strcpy(di.userid1, key->userid);
	di.keyserial1 = key->keyserial;
	*di.userid2 = 0;
	di.keyserial2 = 0;
	di.doc = src;
	di.doc_len = nsrc;
	di.strip_doc_len = nsrc;
	di.sig = temp.getptr();
	di.sig_len = rc;

	return ArmorDoc(dst, ndst, &di);
}


int Crypt_OpenPublicKey_Internal(int eng, const char *src, int nsrc, unsigned long keyserial, IPRIV_KEY *key,
							 IPRIV_KEY *cakey, int imp)
{
	if (key)
		memset((char *) key, 0, sizeof(*key));

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (imp) {
		if (!crypt_eng_list[eng].public_key_import)
			return CRYPT_ERR_NOT_SUPPORT;
	} else {
		if (!crypt_eng_list[eng].public_key_new)
			return CRYPT_ERR_NOT_SUPPORT;
	}

	if (cakey) {
		if (cakey->eng < 0 || cakey->eng >= IPRIV_MAX_ENG_NUM)
			return CRYPT_ERR_INVALID_ENG;
		if (!crypt_eng_list[cakey->eng].is_ready)
			return CRYPT_ERR_ENG_NOT_READY;
	}

	IPRIV_KEY_BODY k;

	memset((char *) &k, 0, sizeof(k));

	int rc = Crypt_ReadPublicKey(src, nsrc, keyserial, &k, cakey, cakey ? crypt_eng_list + cakey->eng : 0);

	if (rc < 0)
		return rc;

	if (imp) {
		rc = crypt_eng_list[eng].public_key_import(&k);
	} else {
		key->keyserial = k.keyserial;
		strcpy(key->userid, k.userid);
		key->eng = eng;
		key->type = IPRIV_KEY_TYPE_RSA_PUBLIC;
		key->timestamp=k.timestamp;

                fix_key_data(&k,key);

		rc = crypt_eng_list[eng].public_key_new(&k, key);
	}

	memset((char *) &k, 0, sizeof(k));

	return rc;
}

int IPRIVAPI Crypt_OpenPublicKey(int eng, const char *src, int nsrc, unsigned long keyserial, IPRIV_KEY *key,
								 IPRIV_KEY *cakey)
{
	return Crypt_OpenPublicKey_Internal(eng, src, nsrc, keyserial, key, cakey, 0);
}

int IPRIVAPI Crypt_OpenPublicKey2(int eng, const char *src, int nsrc, IPRIV_KEY *key)
{
	if (key)
		memset((char *) key, 0, sizeof(*key));

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].public_key_new)
		return CRYPT_ERR_NOT_SUPPORT;

	IPRIV_KEY_BODY k;

	memset((char *) &k, 0, sizeof(k));

	int rc = Crypt_ReadPublicKey2(src, nsrc, &k);

	if (rc < 0)
		return rc;

	key->keyserial = k.keyserial;
	strcpy(key->userid, k.userid);
	key->eng = eng;
	key->type = IPRIV_KEY_TYPE_RSA_PUBLIC;
	key->timestamp=k.timestamp;

        fix_key_data(&k,key);

	rc = crypt_eng_list[eng].public_key_new(&k, key);

	memset((char *) &k, 0, sizeof(k));

	return rc;
}

int Crypt_OpenPublicKeyFromFile_Internal(int eng, const char *path, unsigned long keyserial, IPRIV_KEY *key,
										 IPRIV_KEY *cakey, int imp)
{
	if (key)
		memset((char *) key, 0, sizeof(*key));

	MemBuf temp(8192);

	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;
	FILE *fp = fopen(path, "rb");

	if (!fp)
		return CRYPT_ERR_FILE_NOT_FOUND;
	int rc = fread(temp.getptr(), 1, temp.getlen(), fp);

	fclose(fp);
	if (!rc)
		return CRYPT_ERR_CANT_READ_FILE;
	return Crypt_OpenPublicKey_Internal(eng, temp.getptr(), rc, keyserial, key, cakey, imp);
}

int IPRIVAPI Crypt_OpenPublicKeyFromFile(int eng, const char *path, unsigned long keyserial, IPRIV_KEY *key,
										 IPRIV_KEY *cakey)
{
	return Crypt_OpenPublicKeyFromFile_Internal(eng, path, keyserial, key, cakey, 0);
}

int IPRIVAPI Crypt_OpenPublicKeyFromStore(int eng, unsigned long keyserial, IPRIV_KEY *key)
{
	memset((char *) key, 0, sizeof(*key));

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].public_key_new)
		return CRYPT_ERR_NOT_SUPPORT;

	IPRIV_KEY_BODY k;

	memset((char *) &k, 0, sizeof(k));
	k.keyserial = keyserial;
	key->keyserial = k.keyserial;
	key->eng = eng;
	key->type = IPRIV_KEY_TYPE_RSA_PUBLIC;

	int rc = crypt_eng_list[eng].public_key_new(&k, key);

	memset((char *) &k, 0, sizeof(k));

	return rc;
}

int IPRIVAPI Crypt_Verify(const char *src, int nsrc, const char **pdst, int *pndst, IPRIV_KEY *key)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (nsrc < 0)
		nsrc = strlen(src);

	doc_info di;
	int rc = DearmorDoc(src, nsrc, &di);

	if (rc < 0)
		return rc;

	if (strcmp(di.type, "SM"))
		return CRYPT_ERR_DOCTYPE;

	rc = Crypt_VerifyPacket(di.doc, di.doc_len, di.sig, di.sig_len, key, 0, 0, crypt_eng_list + eng);
	if (rc < 0)
		return rc;
	if (pdst)
		*pdst = di.doc;
	if (pndst)
		*pndst = di.doc_len;
	return rc;
}

int IPRIVAPI Crypt_ExportSecretKey(char *dst, int ndst, const char *passwd, IPRIV_KEY *key)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].secret_key_export)
		return CRYPT_ERR_NOT_SUPPORT;

	IPRIV_KEY_BODY k;

	memset((char *) &k, 0, sizeof(k));

	int rc = crypt_eng_list[eng].secret_key_export(&k, key);

	if (rc)
		return rc;

	k.version = PGP_VER_3;
	k.type = PGP_TAG_SECRET_KEY;
	k.keyserial = key->keyserial;
	strcpy(k.userid, key->userid);
	k.timestamp = (unsigned long) time(0);
	k.validity = 0;
	k.alg = RSA_ALGORITHM_BYTE;

	unsigned char iv[IDEABLOCKSIZE];

	if (crypt_eng_list[eng].gen_random_bytes)
		crypt_eng_list[eng].gen_random_bytes(iv, sizeof(iv));

	rc = Crypt_WriteSecretKey(dst, ndst, passwd, &k, iv, sizeof(iv));
	memset((char *) &k, 0, sizeof(k));
	return rc;
}

int IPRIVAPI Crypt_ExportSecretKeyToFile(const char *path, const char *passwd, IPRIV_KEY *key)
{
	MemBuf temp(4096);

	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	int rc = Crypt_ExportSecretKey(temp.getptr(), temp.getlen(), passwd, key);

	if (rc <= 0)
		return rc;

	FILE *fp = fopen(path, "wb");

	if (!fp)
		return CRYPT_ERR_CREATE_FILE;
	rc = fwrite(temp.getptr(), 1, rc, fp);
	rc += fprintf(fp, "\r\n");
	fclose(fp);

	return rc > 0 ? rc : CRYPT_ERR_CANT_WRITE_FILE;
}


int IPRIVAPI Crypt_ExportPublicKey(char *dst, int ndst, IPRIV_KEY *key, IPRIV_KEY *cakey)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].public_key_export)
		return CRYPT_ERR_NOT_SUPPORT;

	IPRIV_KEY_BODY k;

	memset((char *) &k, 0, sizeof(k));

	int rc = crypt_eng_list[eng].public_key_export(&k, key);

	if (rc)
		return rc;

	k.version = PGP_VER_3;
	k.type = PGP_TAG_PUBLIC_KEY;
	k.keyserial = key->keyserial;
	strcpy(k.userid, key->userid);
	k.timestamp = key->timestamp ? key->timestamp : (unsigned long) time(0);
	k.validity = 0;
	k.alg = RSA_ALGORITHM_BYTE;

	fix_key_body_data(eng,&k);

	rc = Crypt_WritePublicKey(dst, ndst, &k, cakey, crypt_eng_list + eng, cakey ? crypt_eng_list + cakey->eng : crypt_eng_list + eng);

	return rc;
}


int IPRIVAPI Crypt_ExportPublicKeyToFile(const char *path, IPRIV_KEY *key, IPRIV_KEY *cakey)
{
	MemBuf temp(8192);
	MemBuf key_body(2048);

	if (!temp.getlen() || !key_body.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;

	int len = 0;

	FILE *fp = fopen(path, "rb");

	if (fp) {
		len = fread(temp.getptr(), 1, temp.getlen(), fp);
		fclose(fp);
	}

	int cut_offset = 0;
	int cut_len = 0;

	if (len > 0) {
		doc_info di;

		for (int offset = 0;;) {
			int n = DearmorDoc(temp.getptr() + offset, len - offset, &di);

//			fflush(stdout);
			if (n <= 0)
				break;
			if (di.keyserial1 == key->keyserial) {
				cut_offset = offset;
				cut_len = n;
			}
			offset += n;
		}
	}

	int key_len = Crypt_ExportPublicKey(key_body.getptr(), key_body.getlen(), key, cakey);

	if (key_len <= 0)
		return key_len;

	int rc = 0;

	if (!cut_len) { 	// key is not found
		fp = fopen(path, "ab");
		if (!fp)
			return CRYPT_ERR_CREATE_FILE;
		rc = fwrite(key_body.getptr(), 1, key_len, fp);
		rc += fprintf(fp, "\r\n");
		fclose(fp);
	} else {
		fp = fopen(path, "wb");
		if (!fp)
			return CRYPT_ERR_CREATE_FILE;
		rc += fwrite(temp.getptr(), 1, cut_offset, fp);
		rc += fwrite(key_body.getptr(), 1, key_len, fp);
		rc += fprintf(fp, "\r\n");
		rc += fwrite(temp.getptr() + cut_offset + cut_len, 1, len - (cut_offset + cut_len), fp);
		fclose(fp);
	}

	return rc > 0 ? rc : CRYPT_ERR_CANT_WRITE_FILE;
}

int IPRIVAPI Crypt_ImportSecretKey(int eng, const char *src, int nsrc, const char *passwd)
{
	return Crypt_OpenSecretKey_Internal(eng, src, nsrc, passwd, 0, 1);
}

int IPRIVAPI Crypt_ImportSecretKeyFromFile(int eng, const char *path, const char *passwd)
{
	return Crypt_OpenSecretKeyFromFile_Internal(eng, path, passwd, 0, 1);
}

int IPRIVAPI Crypt_ImportPublicKey(int eng, const char *src, int nsrc, unsigned long keyserial,
								   IPRIV_KEY *cakey)
{
	return Crypt_OpenPublicKey_Internal(eng, src, nsrc, keyserial, 0, cakey, 1);
}

int IPRIVAPI Crypt_ImportPublicKeyFromFile(int eng, const char *path, unsigned long keyserial, IPRIV_KEY *cakey)
{
	return Crypt_OpenPublicKeyFromFile_Internal(eng, path, keyserial, 0, cakey, 1);
}

int IPRIVAPI Crypt_GenKeyCard(char *dst, int ndst, const char *userid, unsigned long keyserial)
{
#ifdef WITHOUT_KEYGEN
	return CRYPT_ERR_NOT_SUPPORT;
#else
	return CryptWriteKeyCard(dst, ndst, keyserial, userid);
#endif
}

int IPRIVAPI Crypt_GenKeyCardToFile(const char *path, const char *userid, unsigned long keyserial)
{
	MemBuf temp(512);

	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;
	int rc = Crypt_GenKeyCard(temp.getptr(), temp.getlen(), userid, keyserial);

	if (rc <= 0)
		return 0;
	FILE *fp = fopen(path, "wb");

	if (!fp)
		return CRYPT_ERR_CREATE_FILE;
	rc = fwrite(temp.getptr(), 1, rc, fp);
	fclose(fp);
	return rc;
}


int IPRIVAPI Crypt_GenKey(int eng, const char *src, int nsrc, IPRIV_KEY *sec, IPRIV_KEY *pub, int bits)
{
#ifdef WITHOUT_KEYGEN
	return CRYPT_ERR_NOT_SUPPORT;
#else
	memset((char *) sec, 0, sizeof(*sec));
	memset((char *) pub, 0, sizeof(*pub));

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].genkey)
		return CRYPT_ERR_NOT_SUPPORT;

	unsigned long keyserial = 0;
	char userid[MAX_USERID_LENGTH + 1] = "";
	int rc = CryptReadKeyCard(src, nsrc, &keyserial, userid);

	if (rc < 0)
		return rc;
	sec->eng = pub->eng = eng;
	sec->type = IPRIV_KEY_TYPE_RSA_SECRET;
	pub->type = IPRIV_KEY_TYPE_RSA_PUBLIC;
	sec->keyserial = pub->keyserial = keyserial;

	strcpy(sec->userid, userid);
	strcpy(pub->userid, userid);

	return crypt_eng_list[eng].genkey(sec, pub, bits);
#endif
}

int IPRIVAPI Crypt_GenKeyFromFile(int eng, const char *keycardpath, IPRIV_KEY *sec, IPRIV_KEY *pub, int bits)
{
	MemBuf temp(1024);

	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;
	FILE *fp = fopen(keycardpath, "rb");

	if (!fp)
		return CRYPT_ERR_FILE_NOT_FOUND;
	int rc = fread(temp.getptr(), 1, temp.getlen(), fp);

	fclose(fp);
	if (!rc)
		return CRYPT_ERR_CANT_READ_FILE;
	return Crypt_GenKey(eng, temp.getptr(), rc, sec, pub, bits);
}

int IPRIVAPI Crypt_GenKey2(int eng, unsigned long keyserial, const char *userid, IPRIV_KEY *sec,
						   IPRIV_KEY *pub, int bits)
{
#ifdef WITHOUT_KEYGEN
	return CRYPT_ERR_NOT_SUPPORT;
#else
	memset((char *) sec, 0, sizeof(*sec));
	memset((char *) pub, 0, sizeof(*pub));

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].genkey)
		return CRYPT_ERR_NOT_SUPPORT;

	sec->eng = pub->eng = eng;
	sec->type = IPRIV_KEY_TYPE_RSA_SECRET;
	pub->type = IPRIV_KEY_TYPE_RSA_PUBLIC;
	sec->keyserial = pub->keyserial = keyserial;

	strcpy(sec->userid, userid);
	strcpy(pub->userid, userid);

	return crypt_eng_list[eng].genkey(sec, pub, bits);
#endif
}

int IPRIVAPI Crypt_ReadKeyCardFromFile(const char *path, unsigned long *keyserial, char *userid)
{
#ifdef WITHOUT_KEYGEN
	return CRYPT_ERR_NOT_SUPPORT;
#else
	*keyserial = 0;
	*userid = 0;
	MemBuf temp(256);

	if (!temp.getlen())
		return CRYPT_ERR_OUT_OF_MEMORY;
	FILE *fp = fopen(path, "rb");

	if (!fp)
		return CRYPT_ERR_FILE_NOT_FOUND;
	int rc = fread(temp.getptr(), 1, temp.getlen(), fp);

	fclose(fp);

	return CryptReadKeyCard(temp.getptr(), rc, keyserial, userid);
#endif
}

/*
  Symmetrical encryption based on IDEA.
  Not compatible with PGP or INIST

  Format: base64(type|LL|key|LLLL|data)
	type - 1 byte identifier (01)
	LL - length of the next block
*/
int IPRIVAPI Crypt_EncryptLong(const char *src, int nsrc, char *dst, int ndst, IPRIV_KEY *key)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].public_key_encrypt)
		return CRYPT_ERR_NOT_SUPPORT;

	if (nsrc < 0)
		nsrc = strlen(src)+1;	// для строк сохраним конечный ноль
	if (!nsrc) {
		*dst = 0;
		return 0;
	}

	// создаем сессионный ключ
	unsigned char ideakey[IDEAKEYSIZE];
	if (crypt_eng_list[eng].gen_random_bytes)
		crypt_eng_list[eng].gen_random_bytes(ideakey, sizeof(ideakey));
	else
		return CRYPT_ERR_NOT_SUPPORT;

	// зашифроввываем ключ, чтобы узнать длину
	unsigned char mpi[MAX_MPI_LENGTH];
	int rc = crypt_eng_list[eng].public_key_encrypt(ideakey, sizeof(ideakey), mpi, sizeof(mpi), key);
	if (rc) return rc;

	unsigned char *p = mpi;
	while (p < mpi + MAX_MPI_LENGTH && !*p)
		p++;
	uint16 key_len = sizeof(mpi) - (p - mpi);	// длина зашифрованного ключа

	// подготовить пакет с зашифрованными данными
	int record_len = key_len + nsrc + 7;
	unsigned char *record = (unsigned char *) i_malloc(record_len);
	if (!record)
		return CRYPT_ERR_OUT_OF_MEMORY;

	*record = IPRIV_SYMM_IDEA;	// код алгоритма

	uint16 tmp1 = rotate16(key_len);	// длина зашифрованного ключа
	memcpy(record+1, &tmp1, sizeof(tmp1));

	memcpy(record+3, mpi+(sizeof(mpi)-key_len), key_len);		// сам зашифрованный ключ

	uint32 tmp2 = rotate32(nsrc);	// длина данных
	memcpy(record+key_len+3, &tmp2, sizeof(tmp2));

	IdeaCfbContext cfb;
	ideaCfbInit(&cfb, ideakey);
	ideaCfbEncrypt(&cfb, (unsigned char *)src, record+key_len+7, nsrc);	// записать зашифрованные данные
	ideaCfbDestroy(&cfb);
	memset(ideakey, 0, sizeof(ideakey));

	// преобразовать в base64
	unsigned char *b64_record = (unsigned char *) i_malloc(record_len*2);	// с запасом
	if (!b64_record) {
		i_free(record);
		return CRYPT_ERR_OUT_OF_MEMORY;
	}
	int n = radix64encode((char *) record, record_len, (char *) b64_record, record_len*2);
	if (n <= 0) {
		i_free(b64_record);
		i_free(record);
		return CRYPT_ERR_RADIX_ENCODE;
	}

	if (ndst > n && dst) {
		memcpy(dst, b64_record, n);
		dst[n] = 0;
	} else {
		i_free(b64_record);
		i_free(record);
		return CRYPT_ERR_OUT_OF_MEMORY;
	}

	i_free(b64_record);
	i_free(record);

	return n;
}

int IPRIVAPI Crypt_DecryptLong(const char *src, int nsrc, char *dst, int ndst, IPRIV_KEY *key)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].secret_key_decrypt)
		return CRYPT_ERR_NOT_SUPPORT;

	if (nsrc < 0)
		nsrc = strlen(src);

	if (!nsrc) {
		*dst = 0;
		return 0;
	}

	// раскодируем из base64
	unsigned char *record = (unsigned char *) i_malloc(nsrc);
	if (!record)
		return CRYPT_ERR_OUT_OF_MEMORY;
	int n=radix64decode(src, nsrc, (char *) record, nsrc);
	if (n <= 0) {
		i_free(record);
		return CRYPT_ERR_RADIX_DECODE;
	}
	if (*record != IPRIV_SYMM_IDEA) {
		i_free(record);
		return CRYPT_ERR_UNKNOWN_ALG;
	}

	uint16 key_len;
	memcpy(&key_len, record+1, sizeof(key_len));
	key_len = rotate16(key_len);

	// расшифровать сессионный ключ
	unsigned char ideakey[IDEAKEYSIZE];
	int rc = crypt_eng_list[eng].secret_key_decrypt(record+3, key_len, ideakey, sizeof(ideakey), key);
	if (rc <= 0) {
		i_free(record);
		return rc;
	}

	uint32 data_len;
	memcpy(&data_len, record+key_len+3, sizeof(data_len));
	data_len = rotate32(data_len);
	if (ndst < (int) data_len) {
		i_free(record);
		return CRYPT_ERR_OUT_OF_MEMORY;
	}

	// расшифровываем сообщение
	IdeaCfbContext cfb;
	ideaCfbInit(&cfb, ideakey);
	ideaCfbDecrypt(&cfb, record+key_len+7, (unsigned char *) dst, data_len);
	ideaCfbDestroy(&cfb);
	memset(ideakey, 0, sizeof(ideakey));

	i_free(record);
	return data_len;
}

int IPRIVAPI Crypt_Encrypt(const char *src, int nsrc, char *dst, int ndst, IPRIV_KEY *key)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].public_key_encrypt)
		return CRYPT_ERR_NOT_SUPPORT;

	if (nsrc < 0)
		nsrc = strlen(src);

	if (!nsrc) {
		*dst = 0;
		return 0;
	}

	unsigned char mpi[MAX_MPI_LENGTH];
	int rc = crypt_eng_list[eng].public_key_encrypt((unsigned char *) src, nsrc, mpi, sizeof(mpi), key);
	if (rc) return rc;

	unsigned char *p = mpi;
	while (p < mpi + MAX_MPI_LENGTH && !*p)
		p++;
	int len = sizeof(mpi) - (p - mpi);

	if (len*2 >= ndst)
		return CRYPT_ERR_BAD_ARGS;

	static const char hex[] = "0123456789abcdef";

	int j = 0;

	for (int i = 0; i < len; i++, j += 2) {
		dst[j] = hex[(p[i] >> 4) & 0x0f];
		dst[j + 1] = hex[p[i] & 0x0f];
	}
	dst[j] = 0;

	return j;
}

int IPRIVAPI Crypt_Decrypt(const char *src, int nsrc, char *dst, int ndst, IPRIV_KEY *key)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (!crypt_eng_list[eng].secret_key_decrypt)
		return CRYPT_ERR_NOT_SUPPORT;

	if (nsrc < 0)
		nsrc = strlen(src);

	if (!nsrc) {
		*dst = 0;
		return 0;
	}

	int len = nsrc / 2;

	if (nsrc % 2 || len > MAX_MPI_LENGTH)
		return CRYPT_ERR_INVALID_FORMAT;

	static const unsigned char hex[256] = {
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
		0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff
	};

	unsigned char mpi[MAX_MPI_LENGTH];

	for (int i = 0, j = 0; i < nsrc; i += 2, j++) {
		unsigned char h1 = hex[(int) src[i]];
		unsigned char h2 = hex[(int) src[i + 1]];

		if (h1 & 0xf0 || h2 & 0xf0)
			return CRYPT_ERR_INVALID_FORMAT;
		mpi[j] = ((h1 << 4) & 0xf0) | (h2 & 0x0f);
	}

	int rc = crypt_eng_list[eng].secret_key_decrypt(mpi, len, (unsigned char *) dst, ndst, key);
	if (rc <= 0)
		return rc;
	if (ndst > rc) {
		dst[rc] = 0;
		return rc;
	}
	dst[ndst - 1] = 0;
	return ndst - 1;
}

int IPRIVAPI Crypt_Sign2(const char *src, int nsrc, char *dst, int ndst, IPRIV_KEY *key)
{
    return Crypt_Sign2Ex(src,nsrc,dst,ndst,key,__ipriv_hash_alg);
}

int IPRIVAPI Crypt_Sign2Ex(const char *src, int nsrc, char *dst, int ndst, IPRIV_KEY *key, int alg)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (nsrc < 0)
		nsrc = strlen(src);

	return Crypt_SignPacket(src, nsrc, key, dst, ndst, 0, 0, crypt_eng_list + eng, alg);
}

int IPRIVAPI Crypt_Verify2(const char *src, int nsrc, Crypt_FindPublicKey_t find_key, char *info,
						   int info_len, unsigned long *pkeyserial)
{
	if (nsrc < 0)
		nsrc = strlen(src);

	int n = 0;

	for (; n < nsrc; n++)
		if (src[n] != ' ' && src[n] != '\t' && src[n] != '\r' && src[n] != '\n')
			break;

	src = src + n;
	nsrc -= n;

	MemBuf buf(nsrc + 1);
	char *p = buf.getptr();

	int ch = 0;

	n = 0;
	for (int i = 0; i < nsrc; i++) {
		if (src[i] == ' ' || src[i] == '\t') {
			if (ch != ' ')
				ch = p[n++] = ' ';
		} else if (src[i] == '\r' || src[i] == '\n') {
			if (ch != '\n')
				ch = p[n++] = '\n';
		} else {
			((unsigned char *) p)[n++] = ((unsigned char *) src)[i];
			ch = 0;
		}
	}
	while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\n'))
		n--;
	p[n] = 0;

	static const char beg_sig[] = "BEGIN SIGNATURE";
	static const char end_sig[] = "END SIGNATURE";

	char *beg = strstr(p, beg_sig);

	if (!beg)
		return CRYPT_ERR_INVALID_FORMAT;
	n = beg - p;
	*beg = 0;
	beg = beg + sizeof(beg_sig) - 1;
	while (*beg && (*beg == '\r' || *beg == '\n'))
		beg++;

	char *end = strstr(beg, end_sig);

	if (!end)
		return CRYPT_ERR_INVALID_FORMAT;
	*end = 0;

	while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\n'))
		n--;
	p[n] = 0;


	IPRIV_SIGNATURE sig;

	memset((char *) &sig, 0, sizeof(sig));
	{
		MemBuf temp(2048);

		if (!temp.getlen())
			return CRYPT_ERR_OUT_OF_MEMORY;
		int rc = radix64decode(beg, end - beg, temp.getptr(), temp.getlen());

		if (rc <= 0)
			return CRYPT_ERR_RADIX_DECODE;

		rc = read_packet(temp.getptr(), rc, 0, 0, &sig, 0, 0, 0);
		if (rc < 0)
			return rc;
	}

	if (!sig.keyserial)
		return CRYPT_ERR_UNKNOWN_SENDER;

	if (pkeyserial)
		*pkeyserial = sig.keyserial;

	IPRIV_KEY key;
	int rc = find_key(sig.keyserial, &key, info, info_len);

	if (rc)
		return rc;


	int eng = key.eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM) {
		Crypt_CloseKey(&key);
		return CRYPT_ERR_INVALID_ENG;
	}
	if (!crypt_eng_list[eng].is_ready) {
		Crypt_CloseKey(&key);
		return CRYPT_ERR_ENG_NOT_READY;
	}
//  printf("<%i>\n%s",n,p);
	rc = Crypt_VerifyPacket(p, n, beg, end - beg, &key, 0, 0, crypt_eng_list + eng);

	Crypt_CloseKey(&key);

	return rc;
}

int IPRIVAPI Crypt_Verify_Detached(const char *src, int nsrc, const char **pdst, int *pndst, IPRIV_KEY *key)
{
	if (nsrc < 0)
		nsrc = strlen(src);

	int n = 0;

	for (; n < nsrc; n++)
		if (src[n] != ' ' && src[n] != '\t' && src[n] != '\r' && src[n] != '\n')
			break;

	src = src + n;
	nsrc -= n;

	MemBuf buf(nsrc + 1);
	char *p = buf.getptr();

	int ch = 0;

	n = 0;
	for (int i = 0; i < nsrc; i++) {
		if (src[i] == ' ' || src[i] == '\t') {
			if (ch != ' ')
				ch = p[n++] = ' ';
		} else if (src[i] == '\r' || src[i] == '\n') {
			if (ch != '\n')
				ch = p[n++] = '\n';
		} else {
			((unsigned char *) p)[n++] = ((unsigned char *) src)[i];
			ch = 0;
		}
	}
	while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\n'))
		n--;
	p[n] = 0;

	static const char beg_sig[] = "BEGIN SIGNATURE";
	static const char end_sig[] = "END SIGNATURE";

	char *beg = strstr(p, beg_sig);

	if (!beg)
		return CRYPT_ERR_INVALID_FORMAT;
	n = beg - p;
	*beg = 0;
	beg = beg + sizeof(beg_sig) - 1;
	while (*beg && (*beg == '\r' || *beg == '\n'))
		beg++;

	char *end = strstr(beg, end_sig);

	if (!end)
		return CRYPT_ERR_INVALID_FORMAT;
	*end = 0;

	while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\n'))
		n--;
	p[n] = 0;


	IPRIV_SIGNATURE sig;

	memset((char *) &sig, 0, sizeof(sig));
	{
		MemBuf temp(2048);

		if (!temp.getlen())
			return CRYPT_ERR_OUT_OF_MEMORY;
		int rc = radix64decode(beg, end - beg, temp.getptr(), temp.getlen());

		if (rc <= 0)
			return CRYPT_ERR_RADIX_DECODE;

		rc = read_packet(temp.getptr(), rc, 0, 0, &sig, 0, 0, 0);
		if (rc < 0)
			return rc;
	}

	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	int rc = Crypt_VerifyPacket(p, n, beg, end - beg, key, 0, 0, crypt_eng_list + eng);

	if (!rc) {
		if (pdst)
			*pdst = p;
		if (pndst)
			*pndst = n;
	}

	return rc;
}

int IPRIVAPI Crypt_Verify3(const char *src, int nsrc, const char *sig, int nsig, IPRIV_KEY *key)
{
	int eng = key->eng;

	if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
		return CRYPT_ERR_INVALID_ENG;
	if (!crypt_eng_list[eng].is_ready)
		return CRYPT_ERR_ENG_NOT_READY;

	if (nsrc < 0)
		nsrc = strlen(src);

	if (nsig < 0)
		nsig = strlen(sig);

	int rc = Crypt_VerifyPacket(src, nsrc, sig, nsig, key, 0, 0, crypt_eng_list + eng);

	return rc;
}

int IPRIVAPI Crypt_GetKeyBits(IPRIV_KEY* key)
{
    int eng = key->eng;

    if (eng < 0 || eng >= IPRIV_MAX_ENG_NUM)
	return CRYPT_ERR_INVALID_ENG;

    if (!crypt_eng_list[eng].is_ready)
	return CRYPT_ERR_ENG_NOT_READY;

    return bits2bytes(Crypt_Ctrl(eng,IPRIV_ENGCMD_GET_KEY_LENGTH,key))*8;
}
