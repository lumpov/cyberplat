var assert = require('assert');
var Parser = require('../lib/parser');
var fs = require('fs');
var errors = require('../lib/errors');

describe("Parser", function() {
    it("check parse message", function() {
        var parser = new Parser({}, null, errors);
        //var parser = new Parser({}, new Logger(), errors);
        
        var message = fs.readFileSync('./tests/message.txt', 'utf8');

        var parsed = parser.parse(message);
        //console.log(parsed);

        assert.equal('10.12.2016 21:00:05', parsed.DATE);
    });
});