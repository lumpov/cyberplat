"use strict";

var assert = require("assert");
var nbind = require("nbind");
var lib = nbind.init().lib;

var Crypto = function (settings, logger) {
    assert(settings);
    assert(settings.secretKey);
    assert(settings.secretPhrase);

    var log = function() {
        if (logger) {
            logger.log(arguments[0], arguments[1]);
        }
    };

    var rc = lib.IprivKey.initialize();
    if (rc !== 0) {
        log('init unsuccessful', rc);
        return;
    }

    var secretKey = new lib.IprivKey();

    rc = secretKey.OpenSecretKeyFromFile(settings.secretKey, settings.secretPhrase);
    if (rc !== 0) {
        log('cannot open secret key from file', rc);
        return false;
    }
    
    var sign = function(message) {

		// TODO: Solve the problem with the encoding of win1251
        var srcBuffer = Buffer.from(message);
        var result = Buffer.alloc(srcBuffer.length + 4096, 0);
        
        var rc = secretKey.Sign(srcBuffer, result);
        if (rc > 0) {
            log("sign message successful", rc);

            log("----------result:", result);
            log("----------length:", result.length); 
			
			// TODO: Solve the problem with the encoding of win1251
            return result.toString();
        } else {
            console.log("cannot sign message", rc, message);
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
