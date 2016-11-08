// wrapper for PHP
// some instructions for Windows project: http://blog.slickedit.com/?p=128

#ifdef _WIN32
  #include "zend_config.w32.h"
#endif
#include "php.h"
#include "../../../libipriv.h"

#define MAX_OVERHEAD	1024
#define DEFAULT_ERROR	-1000

/* declaration of functions to be exported */
//ZEND_FUNCTION(DoubleUp);
ZEND_FUNCTION(ipriv_sign);
ZEND_FUNCTION(ipriv_verify);
ZEND_FUNCTION(ipriv_sign2);
ZEND_FUNCTION(ipriv_verify2);
ZEND_FUNCTION(ipriv_encrypt);
ZEND_FUNCTION(ipriv_decrypt);

ZEND_MINIT_FUNCTION(ipriv);
ZEND_MSHUTDOWN_FUNCTION(ipriv);

/* compiled function list so Zend knows what's in this module */
zend_function_entry ipriv_functions[] = {
	ZEND_FE(ipriv_sign, NULL)
	ZEND_FE(ipriv_verify, NULL)
	ZEND_FE(ipriv_sign2, NULL)
	ZEND_FE(ipriv_verify2, NULL)
	ZEND_FE(ipriv_encrypt, NULL)
	ZEND_FE(ipriv_decrypt, NULL)
	{NULL, NULL, NULL}
};

/* compiled module information */
zend_module_entry ipriv_module_entry = {
	STANDARD_MODULE_HEADER,
	"IprivPG Module",
	ipriv_functions,
	ZEND_MINIT(ipriv),
	ZEND_MSHUTDOWN(ipriv),
	NULL, NULL, NULL,
	NO_VERSION_YET, STANDARD_MODULE_PROPERTIES
};

/* implement standard "stub" routine to introduce ourselves to Zend */
ZEND_GET_MODULE(ipriv)

/* DoubleUp function */
/*
ZEND_FUNCTION(DoubleUp)
{
	long theValue = 0;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "l", &theValue) == FAILURE) {
		RETURN_NULL();
	}
	theValue *= 2;

	RETURN_LONG(theValue);
}
*/

ZEND_MINIT_FUNCTION(ipriv)
{
	Crypt_Initialize();
	return SUCCESS;
}

ZEND_MSHUTDOWN_FUNCTION(ipriv)
{
	Crypt_Done();
	return SUCCESS;
}

ZEND_FUNCTION(ipriv_sign)
{
	char *content;
	int content_len;
	char *key;
	int key_len;
	char *pass;
	int pass_len;
	IPRIV_KEY sec_key;
	char *tmp = 0;
	int rc = DEFAULT_ERROR;

	array_init(return_value);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &content, &content_len,
			&key, &key_len, &pass, &pass_len) == FAILURE) {
		add_next_index_long(return_value, -1);
		add_next_index_null(return_value);
		return;
	}

	rc = Crypt_OpenSecretKey(IPRIV_ENGINE_DEFAULT, key, key_len, pass, &sec_key);
	if (!rc) {
		tmp = (char *) malloc(content_len + MAX_OVERHEAD);
		if (tmp) {
			rc = Crypt_Sign(content, content_len, tmp, content_len + MAX_OVERHEAD, &sec_key);
			if (!rc)
				rc = DEFAULT_ERROR - 1;
		}
		Crypt_CloseKey(&sec_key);
	}

	add_next_index_long(return_value, rc < 0 ? rc : 0);
	if (rc > 0)
		add_next_index_stringl(return_value, tmp, rc, 1);
	else
		add_next_index_null(return_value);

	if (tmp) free(tmp);
}

ZEND_FUNCTION(ipriv_sign2)
{
	char *content;
	int content_len;
	char *key;
	int key_len;
	char *pass;
	int pass_len;
	IPRIV_KEY sec_key;
	char *tmp = 0;
	int rc = DEFAULT_ERROR;

	array_init(return_value);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &content, &content_len,
			&key, &key_len, &pass, &pass_len) == FAILURE) {
		add_next_index_long(return_value, -1);
		add_next_index_null(return_value);
		return;
	}

	rc = Crypt_OpenSecretKey(IPRIV_ENGINE_DEFAULT, key, key_len, pass, &sec_key);
	if (!rc) {
		tmp = (char *) malloc(content_len + MAX_OVERHEAD);
		if (tmp) {
			rc = Crypt_Sign2(content, content_len, tmp, content_len + MAX_OVERHEAD, &sec_key);
			if (!rc)
				rc = DEFAULT_ERROR - 1;
		}
		Crypt_CloseKey(&sec_key);
	}

	add_next_index_long(return_value, rc < 0 ? rc : 0);
	if (rc > 0)
		add_next_index_stringl(return_value, tmp, rc, 1);
	else
		add_next_index_null(return_value);

	if (tmp) free(tmp);
}

ZEND_FUNCTION(ipriv_verify)
{
	char *content;
	int content_len;
	char *key;
	int key_len;
	IPRIV_KEY pub_key;
	const char *dst = 0;
	int ndst = 0;
	int rc = DEFAULT_ERROR;
	long serial = 0;


	array_init(return_value);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|l", &content, &content_len,
			&key, &key_len, &serial) == FAILURE) {
		add_next_index_long(return_value, -1);
		add_next_index_null(return_value);
		return;
	}

	rc = Crypt_OpenPublicKey(IPRIV_ENGINE_DEFAULT, key, key_len, serial, &pub_key, 0);
	if (!rc) {
		rc = Crypt_Verify(content, content_len, &dst, &ndst, &pub_key);
		Crypt_CloseKey(&pub_key);
	}

	add_next_index_long(return_value, rc);
	if (!rc && ndst > 0 && dst)
		add_next_index_stringl(return_value, (char *) dst, ndst, 1);
	else
		add_next_index_null(return_value);
}

ZEND_FUNCTION(ipriv_verify2)
{
	char *content;
	int content_len;
	char *signature;
	int signature_len;
	char *key;
	int key_len;
	IPRIV_KEY pub_key;
	int rc = DEFAULT_ERROR;
	int result = -1;
	long serial = 0;


	array_init(return_value);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss|l", &content, &content_len,
			&signature, &signature_len, &key, &key_len, &serial) == FAILURE) {
		add_next_index_long(return_value, -1);
		//add_next_index_null(return_value);
		return;
	}

	rc = Crypt_OpenPublicKey(IPRIV_ENGINE_DEFAULT, key, key_len, serial, &pub_key, 0);
	if (!rc) {
		result = Crypt_Verify3(content, content_len, signature, signature_len, &pub_key);
		Crypt_CloseKey(&pub_key);
	}

	add_next_index_long(return_value, result);
}

ZEND_FUNCTION(ipriv_encrypt)
{
	char *content;
	int content_len;
	char *key;
	int key_len;
	IPRIV_KEY pub_key;
	char dst[1024];		// requires 256 bytes for 2048 bit keys
	int rc = DEFAULT_ERROR;
	long serial = 0;

	array_init(return_value);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss|l", &content, &content_len,
			&key, &key_len, &serial) == FAILURE) {
		add_next_index_long(return_value, -1);
		add_next_index_null(return_value);
		return;
	}

	rc = Crypt_OpenPublicKey(IPRIV_ENGINE_DEFAULT, key, key_len, serial, &pub_key, 0);
	if (!rc) {
		rc = Crypt_Encrypt(content, content_len, dst, sizeof(dst), &pub_key);
		Crypt_CloseKey(&pub_key);
	}

	add_next_index_long(return_value, rc);
	if (rc && dst)
		add_next_index_stringl(return_value, (char *) dst, rc, 1);
	else
		add_next_index_null(return_value);
}

ZEND_FUNCTION(ipriv_decrypt)
{
	char *content;
	int content_len;
	char *key;
	int key_len;
	char *pass;
	int pass_len;
	IPRIV_KEY sec_key;
	char dst[1024];
	int rc = DEFAULT_ERROR;

	array_init(return_value);
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &content, &content_len,
			&key, &key_len, &pass, &pass_len) == FAILURE) {
		add_next_index_long(return_value, -1);
		add_next_index_null(return_value);
		return;
	}

	rc = Crypt_OpenSecretKey(IPRIV_ENGINE_DEFAULT, key, key_len, pass, &sec_key);
	if (!rc) {
		rc = Crypt_Decrypt(content, content_len, dst, sizeof(dst), &sec_key);
		if (!rc)
			rc = DEFAULT_ERROR - 1;
		Crypt_CloseKey(&sec_key);
	}

	add_next_index_long(return_value, rc);
	if (rc > 0)
		add_next_index_stringl(return_value, dst, rc, 1);
	else
		add_next_index_null(return_value);

}
