"use strict";

var ffi = require('ffi');
var ref = require('ref');
var struct = require('ref-struct');
var assert = require("assert");
var tracer = require('tracer');
var console = tracer.colorConsole({level:0});

// Типы криптосредств
const IPRIV_ENGINE_RSAREF = 0;  // Библиотека RSAREF
const IPRIV_ENGINE_OPENSSL = 1; // Библиотека OpenSSL
const IPRIV_ENGINE_PKCS11 = 2;  // Интерфейс PKCS11 (частный случай eToken)
const IPRIV_ENGINE_WINCRYPT = 3;    // Интерфейс Microsoft Windows CryptoAPI

var Crypto = function (settings) {

    if (settings.debug) {
        tracer.setLevel('debug');
    } else {
        tracer.setLevel('error');
    }


    var libipriv;
    var engine = IPRIV_ENGINE_RSAREF;

    var init = function () {
        libipriv= ffi.Library(settings.libPath, {
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
        console.debug('init unsuccessful', rc);
        return;
    }

    const srcbuffer = new Buffer(4096);
    srcbuffer.fill(0);

    const buffer = new Buffer(4096);
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
        console.debug('cannot open secret key from file', rc);
    };

    var sign = function(message) {
        srcbuffer.write(message);
        var rc = libipriv.Crypt_Sign(srcbuffer, -1, buffer, 4096, ptrIPrivKey);
        if (rc > 0) {
            console.debug("sign message successful", rc, buffer.toString());
            return buffer.toString();
        } else {
            console.debug("cannot sign message", rc, message);
            return -1;
        }
    };

    var validate = function(message) {
        return;
    };

    return {
        sign: sign,
        validate: validate
    };
};

module.exports = Crypto;