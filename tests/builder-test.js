var assert = require('assert');
var Builder = require('../lib/builder');
var fs = require('fs');
var Logger = require('../lib/logger');

describe("Builder", function() {
    var builder = new Builder({
        AP: 1,
        SD: 2,
        OP: 3,
        debug: true
    }, new Logger());
    
    it("check convert", function() {
        var message = builder.obj2str({ob: 12});
        assert.equal(message,"ob=12");
    });

    it("check valid buildPayCheckMessage", function() {
        var obj = {
            DATE: "12",
            SESSION: 'session',
            AMOUNT: "1.00",
            AMOUNT_ALL: "1.00",
            TERM_ID: "1",
            NUMBER: "1212"
        };

        var message = builder.buildMessage('payCheck', obj);

        var str = [
            "SD=2","AP=1","OP=3",
            "DATE=12","SESSION=session",
            "AMOUNT=1.00", "AMOUNT_ALL=1.00", 
            "TERM_ID=1", "NUMBER=1212", "ACCOUNT=", "REQ_TYPE=0", 
            "PAY_TOOL=0", "COMMENT=", "ACCEPT_KEYS=", 
            "NO_ROUTE=0"
            ].join("\r\n");

        assert.equal(message, str);
    }); 

    it("check invalid buildPayCheckMessage", function() {
        var obj = {
            DATE: "12",
            SESSION: 'session'
            };

        var message = builder.buildMessage('payCheck', obj);
        
        assert.equal(message, false);
    }); 
    
    it("convert encoding", function() {
        var message = "Привет!";
        var encoded = builder.convertEncoding(message);

        var message2 = fs.readFileSync('./tests/cp1251.txt');

        assert.equal(encoded, message2);
    });
    
});