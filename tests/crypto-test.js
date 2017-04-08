var assert = require('assert');
var Crypto = require('../lib/crypto');

describe("Crypto", function() {
    
    it("check sign message", function() {
        /* 
        var crypto = new Crypto({
            debug: true,
            secretKey: "./tests/secret.key",
            secretPhrase: "1111111111"
        }, new Logger());
        */
        
        var crypto = new Crypto({
            secretKey: "./tests/secret.key",
            secretPhrase: "1111111111"
        });

        var signed = crypto.sign("hello=qw");
        
        assert.ok(signed.indexOf("END SIGNATURE") > 0);
    }); 
    
});
