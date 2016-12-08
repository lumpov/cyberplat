var assert = require('assert');
var CyberplatAgent = require('../index')

describe("Cyberplat", function() {
    
    it("check create", function() {
        var cyberplatAgent = new CyberplatAgent({
            crypto: {
                debug: true,
                libPath: './tests/libipriv',
                secretKey: './tests/secret.key',
                secretPhrase: '1111111111'   //password
            },
            settings: {
                AP: 1,
                SD: 2,
                OP: 3
            }
        });

    }); 
    
});