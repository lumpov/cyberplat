"use strict";

var assert = require("assert");
var iprivpg = require("bindings")("iprivpg");

var Crypto = function (settings, logger) {
    assert(settings);
    assert(settings.secretKey);
    assert(settings.secretPhrase);

    var log = function() {
        if (logger) {
            logger.log(arguments[0], arguments[1]);
        }
    };

    var rc = iprivpg.initialize();
    if (rc !== 0) {
        log('init unsuccessful', rc);
        return;
    }

    var secretKey = new iprivpg.IprivKey();
    rc = secretKey.OpenSecretKeyFromFile(settings.secretKey, settings.secretPhrase);
    if (rc !== 0) {
        log('cannot open secret key from file', rc);
        return false;
    }
    
    var publicKey = new iprivpg.IprivKey();
    rc = publicKey.OpenPublicKeyFromFile(settings.publicKey, settings.publicSerial);
    if (rc !== 0) {
        log('cannot open public key from file', rc);
        return false;
    }
    
    var sign = function(message) {

        var result = Buffer.alloc(message.length + 4096, 0, 'binary');
        
        var rc = secretKey.Sign(message, result);
        if (rc > 0) {
            return Buffer.from(result, 0, rc);
        } else {
            console.log("cannot sign message", rc, message);
            log("cannot sign message", rc, message);
            return false;
        }
    };
    
    var validate = function(message) {

        var result = Buffer.alloc(message.length, 0, 'binary');
        
        var rc = publicKey.Verify(message, result);
        if (rc > 0) {
            return Buffer.from(result, 0, rc);
        } else {
            console.log("cannot verify message", rc, message);
            log("cannot verify message", rc, message);
            return false;
        }
    };

    return {
        sign: sign,
        validate: validate
    };
};

module.exports = Crypto;
