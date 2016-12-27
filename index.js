"use strict";

var assert = require("assert");


var Builder = require('./lib/builder');
var Crypto = require('./lib/crypto');
var Client = require('./lib/client');
var Parser = require('./lib/parser');
var Logger = require('./lib/logger');

var errors = require('./lib/errors');

var Cyberplat = function (ops) {

    assert(ops.crypto);
    assert(ops.settings);
    assert(ops.providers);

    if (ops.debug) {
        var logger = new Logger();
    }
    
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
    if (!crypto) {
        throw new Error('no init crypto lib');
    }
    var client = new Client(ops.settings, logger);
    
    var parser = new Parser({}, null, errors);

    var go = function(type, providerid, obj, callback) {
        //assert(providers[providerid])

        var url = null;

        if (providers && providers[providerid] && providers[providerid][type]){
            url = providers[providerid][type];
        }

        if (!url) {callback(null)};

        var message = builder.buildMessage(type, obj);
        var signedMessage = crypto.sign(message);

        if (!signedMessage) {
            throw new Error('no sign message');
        }
        
        var str = signedMessage;    //signedMessage.replace(/\s/g, "+");

        log("signed message:", str);
        //log("trim:", trim(str));

        client.request(url, trim(str), function(response){
            var answer = false;
            // здесь добавить верификацию полученного сообщения
            if (response.ok) {
                answer = parser.parse(response.body);
            };

            callback(answer);
        });
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