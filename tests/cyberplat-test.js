var assert = require('assert');
var Cyberplat = require('../index')

describe("Cyberplat", function() {
    
    it("check create", function(done) {
        var cyberplat = new Cyberplat({
            crypto: {
                debug: true,
                libPath: './tests/libipriv',
                secretKey: './tests/secret.key',
                secretPhrase: '1111111111'   //password
            },
            settings: {
                AP: 1,
                SD: 2,
                OP: 3,
                debug: true
            }
        });

        var obj = {
            DATE: "12",
            SESSION: 'session',
            AMOUNT: "1.00",
            AMOUNT_ALL: "1.00",
            TERM_ID: "1",
            NUMBER: "1212"
        };

        cyberplat.payCheck(obj, function(err, answer) {
            console.log(answer);
            done();
        });

    }); 
    
});