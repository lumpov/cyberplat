var assert = require('assert');
var Builder = require('../lib/builder')

describe("Builder", function() {
    var builder = new Builder({
        AP: 1,
        SD: 2,
        OP: 3,
        debug: true
    });
    
    it("check convert", function() {
        var message = builder.convert({ob: 12});
        assert.equal(message,"ob=12");
    }); 

    it("check valid buildPayCheckMessage", function() {
        var obj = {
            DATE: "12",
            SESSION: 'session',
            AMOUNT: "1.00",
            AMOUNT_ALL: "1.00",
            TERM_ID: "1"
        };

        var message = builder.buildPayCheckMessage(obj);

        var str = [
            "DATE=12","SESSION=session",
            "AMOUNT=1.00", "AMOUNT_ALL=1.00", 
            "TERM_ID=1", "NUMBER=", "REQ_TYPE=0", 
            "PAY_TOOL=0", "COMMENT=", "ACCEPT_KEYS=", 
            "NO_ROUTE=0", "SD=2","AP=1","OP=3"
            ].join("\r\n");

        assert.equal(message, str);
    }); 

    it("check invalid buildPayCheckMessage", function() {
        var obj = {
            DATE: "12",
            SESSION: 'session'
            };

        var message = builder.buildPayCheckMessage(obj);
        
        assert.equal(message, false);
    }); 
    
    
});