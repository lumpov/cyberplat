"use strict";

var ffi = require('ffi');
var ref = require('ref');
var struct = require('ref-struct');
var assert = require("assert");


// Типы криптосредств
const IPRIV_ENGINE_RSAREF = 0;  // Библиотека RSAREF
const IPRIV_ENGINE_OPENSSL = 1; // Библиотека OpenSSL
const IPRIV_ENGINE_PKCS11 = 2;  // Интерфейс PKCS11 (частный случай eToken)
const IPRIV_ENGINE_WINCRYPT = 3;    // Интерфейс Microsoft Windows CryptoAPI

var Crypto = function (settings, logger) {
    assert(settings);
    assert(settings.secretKey);
    assert(settings.secretPhrase);

    var log = function() {
        if (logger) {
            logger.log(arguments[0], arguments[1]);
        }
    };

    var libiprivPath = settings.libPath || '/usr/lib/libipriv/libipriv';

    var libipriv;
    var engine = IPRIV_ENGINE_RSAREF;

    var init = function () {
        libipriv= ffi.Library(libiprivPath, {
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
        return libipriv.Crypt_Initialize();
    };

    var rc = init();
    if (rc !== 0) {
        log('init unsuccessful', rc);
        return;
    }

    const srcbuffer = new Buffer(1024);
    //srcbuffer.fill(0);

    const buffer = new Buffer(1024);
    buffer.fill(0);

    const ptrIPrivKey = new Buffer(32);
    ptrIPrivKey.fill(0);

    const ptrIPubKey1 = new Buffer(32);
  
    const bufSecretKeyPath = new Buffer(1024);
    bufSecretKeyPath.fill(0);
    bufSecretKeyPath.write(settings.secretKey);

    const bufPassword = new Buffer(32);
    bufPassword.fill(0);
    bufPassword.write(settings.secretPhrase);

    var openSecretKeyFromFile = function() {
        return libipriv.Crypt_OpenSecretKeyFromFile(engine, bufSecretKeyPath, bufPassword, ptrIPrivKey);
    };

    var rc = openSecretKeyFromFile();
    if (rc !== 0) {
        log('cannot open secret key from file', rc);
        return false;
    };

    var sign = function(message) {

        srcbuffer.fill(0);
        srcbuffer.write(message);

        var rc = libipriv.Crypt_Sign(srcbuffer, -1, buffer, 1024, ptrIPrivKey);
        if (rc > 0) {
            log("sign message successful", rc);

            var buf = Buffer.from(buffer, 0, rc);
            var mess = buf.toString().substr(0,rc);
            log("----------message:", mess);
            log("----------length", mess.length);
            return mess;
        } else {
            log("cannot sign message", rc, message);
            return false;
        }
    };

    var validate = function(message) {
        return message;
    };

    return {
        sign: sign,
        validate: validate
    };
};

module.exports = Crypto;