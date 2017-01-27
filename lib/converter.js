"use strict";

var iconv = require('iconv-lite');
var windows1251 = require('windows-1251');


var Converter = function (logger) {
 	
 	var log = function() {
        if (logger) {
            logger.log(arguments[0], arguments[1]);
        }
    };

    var convertUTF8toWIN1251 = function (strInUTF8) {        
        //var converted = iconv.encode(strInUTF8, 'win1251');
        var converted = windows1251.encode(strInUTF8, {mode: 'html'});
        log('convert utf8 to win1251:', converted.toString());
        return converted;
    };

    var convertWIN1251toUTF8 = function (strInWIN1251) {
        //var converted = iconv.decode(strInWIN1251, 'win1251');  
        var converted = windows1251.decode(strInWIN1251);
        log('convert win1251 to utf8:', converted);
        return converted;
    };

    return {
    	convertUTF8toWIN1251: convertUTF8toWIN1251, 
    	convertWIN1251toUTF8: convertWIN1251toUTF8
    };
};

module.exports = Converter;