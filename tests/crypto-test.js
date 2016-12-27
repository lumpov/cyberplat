var assert = require('assert');
var Crypto = require('../lib/crypto');

describe("Crypto", function() {
    
    it("check sign message", function() {
        /*
        var crypto = new Crypto({
            debug: true,
            libPath: "./tests/libipriv",
            secretKey: "./tests/secret.key",
            secretPhrase: "1111111111"
        }, new Logger());
        */

        var crypto = new Crypto({
            libPath: "./tests/libipriv",
            secretKey: "./tests/secret.key",
            secretPhrase: "1111111111"
        });

        var crypted = crypto.sign("hello=qw");

        //console.log("crypted", crypted);
    }); 
    
});