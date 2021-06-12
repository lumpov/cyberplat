var assert = require('assert');
var Crypto = require('../lib/crypto');

describe("Crypto", function() {
    
    it("check sign message", function() {
        /* 
        var crypto = new Crypto({
            debug: true,
            secretKey: "./tests/secret.key",
            secretPhrase: "1111111111",
            publicKey: "./tests/pubkeys.key",
            publicSerial: 64182       // serial number of cyberplat key
        }, new Logger());
        */
        
        var crypto = new Crypto({
            secretKey: "./tests/secret.key",
            secretPhrase: "1111111111",
            publicKey: "./tests/pubkeys.key",
            publicSerial: 64182       // serial number of cyberplat key
        });

        var signed = crypto.sign("hello=qw");
        
        console.log('signed message:', signed.toString());
        
        assert.ok(signed.indexOf("END SIGNATURE") > 0);
    }); 
    
});
