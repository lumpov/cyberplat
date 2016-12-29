
var assert = require('assert');
var fs = require('fs');
var iconv = require('iconv-lite');

var Converter = require('../lib/converter');

describe("Converter", function(){ 

    var converter = new Converter();

    it("test encoding utf8 to win1251", function() {
        var message = "Привет!";
        var encoded = converter.convertUTF8toWIN1251(message);  //return buffer

        var message2 = fs.readFileSync('./tests/cp1251.txt');   //return buffer

        assert.equal(encoded.toString(), message2.toString());
    });

    it("test convert win1251 to utf8", function() {
        var message = "Привет!";

        var message2 = fs.readFileSync('./tests/cp1251.txt');
        var encoded = converter.convertWIN1251toUTF8(message2);
        
        assert.equal(encoded.toString(), message);
    });


     it("test convert win1251 to utf8", function() {
        var message = "Привет!";

        var message2 = fs.readFileSync('./tests/cp1251.txt');
        var encoded = converter.convertWIN1251toUTF8(message2);

        var t = new Buffer(message2.toString(), 'binary');        
        
        assert.equal(encoded.toString(), message);
    });
});