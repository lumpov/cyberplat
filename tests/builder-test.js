var assert = require('assert');
var Builder = require('../lib/builder')

describe("Builder", function() {
    var builder = new Builder({
        AP: 1,
        SD: 2,
        OP: 3,
        debug: false
    });
    
    it("check convert", function() {
        var message = builder.convert({ob: 12});
        assert.equal(message,"ob=12");
    }); 

    it("check buildPayCheckMessage", function() {
        var message = builder.buildPayCheckMessage({
            DATE: "12",
            SESSION: 'session',
            AMOUNT: "1.00"            
        });

        var str = [
            "DATE=12","SESSION=session",
            "AMOUNT=1.00","NUMBER=",
            "SD=2","AP=1","OP=3"
            ].join("\r\n");

        assert.equal(message,str);
    }); 
    
    
});