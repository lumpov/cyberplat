var ffi = require('ffi');
var ref = require('ref');
var struct = require('ref-struct');
var assert = require("assert");

// Типы криптосредств
const IPRIV_ENGINE_RSAREF = 0;	// Библиотека RSAREF
const IPRIV_ENGINE_OPENSSL = 1;	// Библиотека OpenSSL
const IPRIV_ENGINE_PKCS11 = 2;	// Интерфейс PKCS11 (частный случай eToken)
const IPRIV_ENGINE_WINCRYPT = 3;	// Интерфейс Microsoft Windows CryptoAPI

/*
// Структура ключа
typedef struct
{
	short eng;				// Тип криптосредства
	short type;				// Тип ключа
	unsigned long keyserial;		// Серийный номер ключа
	char userid[24];			// Код покупателя (минимум MAX_USERID_LENGTH+1)
	void* key;				// Специфические для криптосредства данные
}IPRIV_KEY;
*/
/*
var structIPRIV_KEY = new struct({
  'eng': 'short', //2
  'type': 'short', //2
  'keyserial': 'ulong', //4
  'userid': 'char', //24
  'key': 'short' //2
});

var reftypeIPRIV_KEY = ref.refType(structIPRIV_KEY);
*/




describe("ffi test", function () {
  it("check sign using private key", function () {

    var libipriv = ffi.Library('./tests/libipriv', {
      'Crypt_Initialize':  [ 'int', [ ] ],
      //int IPRIVAPI Crypt_OpenSecretKeyFromFile(int eng,const char* path,const char* passwd,IPRIV_KEY* key);
      'Crypt_OpenSecretKeyFromFile': [ 'int', [ 'int', 'char *', 'char *', 'char *' ] ],
      //int IPRIVAPI Crypt_OpenPublicKeyFromFile(int eng,const char* path,unsigned long keyserial,IPRIV_KEY* key,IPRIV_KEY* cakey);
      'Crypt_OpenPublicKeyFromFile': [ 'int', [ 'int', 'char *', 'ulong', 'char *', 'char *' ] ],
      //int IPRIVAPI Crypt_Sign(const char* src,int nsrc,char* dst,int ndst,IPRIV_KEY* key);
      'Crypt_Sign': [ 'int', [ 'char *', 'int', 'char *', 'int', 'char *' ] ],
      //int IPRIVAPI Crypt_Verify(const char* src,int nsrc,const char** pdst,int* pndst,IPRIV_KEY* key);
      'Crypt_Verify': [ 'int', [ 'char *', 'int', 'char **', 'int *', 'char *' ]],
      //int IPRIVAPI Crypt_CloseKey(IPRIV_KEY* key);
      'Crypt_CloseKey': [ 'int', [ 'char *' ]]
    });


    var engine = IPRIV_ENGINE_RSAREF;
    var rc;

    rc = libipriv.Crypt_Initialize();
    assert.equal(rc, 0);
    console.log('Crypt_Initialize='+rc);

    const srcbuffer = new Buffer(4096);
    srcbuffer.fill(0);
    srcbuffer.write('hello=world');

    const buffer = new Buffer(4096);
    buffer.fill(0);

    const ptrIPrivKey = new Buffer(32);
    ptrIPrivKey.fill(0);

    const ptrIPubKey1 = new Buffer(32);
  

    const bufSecretKeyPath = new Buffer(1024);
    bufSecretKeyPath.fill(0);
    bufSecretKeyPath.write('./tests/secret.key');

    const bufPassword = new Buffer(36);
    bufPassword.fill(0);
    bufPassword.write('1111111111');
    console.log('bufPassword', bufPassword.toString());

    rc = libipriv.Crypt_OpenSecretKeyFromFile(engine, bufSecretKeyPath, bufPassword, ptrIPrivKey);
    console.log('Crypt_OpenSecretKeyFromFile='+rc);
    console.log('ptrIPrivKey='+JSON.stringify(ptrIPrivKey));

    //rc=Crypt_Sign("Hello world",-1,temp,sizeof(temp),&sec);
    rc = libipriv.Crypt_Sign(srcbuffer, -1, buffer, 1024, ptrIPrivKey);
    console.log('Crypt_Sign='+rc);
    console.log('buffer='+buffer);

    rc = libipriv.Crypt_CloseKey(ptrIPrivKey);
    console.log('Crypt_CloseKey ptrIPrivKey='+rc);

  })
})