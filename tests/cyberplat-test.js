var assert = require('assert');
var CyberplatAgent = require('../index')

describe("Cyberplat", function() {
    
    it("check create", function() {
        var cyberplatAgent = new CyberplatAgent({
            crypto: {
                libPath: './tests/libipriv'
            },
            settings: {
                AP: 1,
                SD: 2,
                OP: 3
            }
        });

    }); 
    
});