var assert = require('assert');
var Parser = require('../lib/parser');
var fs = require('fs');
var Logger = require('../lib/logger');


describe("Parser", function() {
    
    it("check parse message", function() {
        var parser = new Parser({}, new Logger());
        
        var message = fs.readFileSync('./tests/message.txt', 'utf8');

        var parsed = parser.parse(message);

        assert.equal('10.12.2016 21:00:05', parsed.object.DATE);
    }); 
    
});