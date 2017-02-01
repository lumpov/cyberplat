"use strict";

var assert = require("assert");

var rest = require('restler');
var qs = require('qs');
var qsIconv = require('qs-iconv');
var win1251 = require('qs-iconv/encoder')('win1251');

var Builder = require('./lib/builder');
var Crypto = require('./lib/crypto');
var Client = require('./lib/client');
var Parser = require('./lib/parser');
var Converter = require('./lib/converter');

var errors = require('./lib/errors');
//var windows1251 = require('windows-1251');
var fs = require('fs');

var Buffer = require('buffer').Buffer;
var Iconv  = require('iconv').Iconv;
var assert = require('assert');

var iconvUtf8ToWin1251 = new Iconv('UTF-8', 'windows-1251');

var iconvWin1251ToUtf8 = new Iconv('windows-1251', 'UTF-8');

var Cyberplat = function (ops) {

    assert(ops.crypto);
    assert(ops.settings);
    assert(ops.providers);

    var logger = null;
    
    if (ops.logger) {
        assert(ops.logger.log);
        logger = ops.logger;
    };
    
    var log = function() {
        if (logger) {
            logger.log(arguments[0], arguments[1]);
        }
    };

    var trim = function(text){
        return text.replace(/^\s+|\s+$/g, '');
    };

    var providers = ops.providers;

    var builder = new Builder(ops.settings, logger);
    var crypto = new Crypto(ops.crypto, logger);
    var converter = new Converter(logger);

    if (!crypto) {
        throw new Error('no init crypto lib');
    }
    
    var client = new Client(ops.settings, logger);
    
    var parser = new Parser({}, null, errors);

    var go = function(type, providerid, obj, callback) {
        var url = null;

        if (providers && providers[providerid] && providers[providerid][type]){
            url = providers[providerid][type];
            log("Provider:", providers[providerid]);
        }

        if (!url) { callback(false) }

        var message = builder.buildMessage(type, obj);
        var encodedMessageToWin1251 = iconvUtf8ToWin1251.convert(message);
        var signedMessage = crypto.sign(encodedMessageToWin1251);

        if (!signedMessage) {
            throw new Error('no sign message');
        }
        
        log("signed Message:", signedMessage);

        var s = signedMessage.toString();
        log('signed message in win1251', s);
 
        var str = iconvWin1251ToUtf8.convert(signedMessage).toString();
        log ('signed message in utf8', str)
            
        var encodedMessage = qs
            .stringify({inputmessage: str}, {encoder: qsIconv.encoder('win1251')})
            .replace(/\%00/g,"")
            .replace(/\%20/g,"+");

        log('encodedMessage', encodedMessage);

        rest.post(url, {
          data: encodedMessage,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
          }
        }).on('complete', function(data) {
          log(data);
        });

        /*
        client.request(url, str, function(response){
            var answer = false;
            // здесь добавить верификацию полученного сообщения
            if (response.ok) {
                log('response.body:', response.body);
                var encodedMessageToUTF8 = converter.convertWIN1251toUTF8(response.body);

                log('convert to utf8 response body', encodedMessageToUTF8);

                answer = parser.parse(encodedMessageToUTF8);
            }

            callback(answer);
        });

        */
    };

    var payCheck = function (providerid, obj, callback) {        
        go('payCheck', providerid, obj, callback);
    };

    var pay = function (providerid, obj, callback) {
        go('pay', providerid, obj, callback);
    };

    var payStatus = function (providerid, obj, callback) {
        go('payStatus', providerid, obj, callback);
    };


    // переделать
    var limitStatus = function (obj, callback) {
        go('limitStatus', null, obj, callback);
    };

    // переделать
    var fillStatus = function (obj, callback) {
        go('fillStatus', null, obj, callback);
    };

    return {
        payCheck: payCheck,
        pay: pay,
        payStatus: payStatus,
        //limitStatus: limitStatus,
        //fillStatus: fillStatus,
        ERRORS: errors
    };
};

module.exports = Cyberplat;