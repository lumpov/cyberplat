"use strict";

var Builder = require('./lib/builder');
var Crypto = require('./lib/crypto');
var Client = require('./lib/client');
var Parser = require('./lib/parser');
//var console = require('tracer').colorConsole({level:0});
var Logger = require('./lib/logger');

var Cyberplat = function (ops) {

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
    }

    var builder = new Builder(ops.settings, logger);
    var crypto = new Crypto(ops.crypto, logger);
    var client = new Client(ops.settings, logger);
    
    var parser = new Parser();

    var go = function(type, providerid, obj, callback) {
        var message = builder.buildMessage(type, obj);
        var signedMessage = crypto.sign(message);
        var str = signedMessage; //signedMessage.replace(/\s/g, "+");

        log("signed message:", str);
        log("length:", trim(str));

        client.request(type, providerid, trim(str), function(response){

            // здесь добавить верификацию полученного сообщения

            var answer = parser.parse(response.body);
            callback(answer.error, answer.object);
        });
    };

    var payCheck = function (providerid, obj, callback) {
        go('payCheck', providerid, obj, callback);
    };

    var pay = function (providerid, obj, callback) {
        go('pay', providerid, obj, callback);
    };

    var payStatus = function (obj, callback) {
        go('payStatus', null, obj, callback);
    };

    var limitStatus = function (obj, callback) {
        go('limitStatus', null, obj, callback);
    };

    var fillStatus = function (obj, callback) {
        go('fillStatus', null, obj, callback);
    };

    return {
        payCheck: payCheck,
        pay: pay,
        payStatus: payStatus,
        limitStatus: limitStatus,
        fillStatus: fillStatus
    };
};

module.exports = Cyberplat;