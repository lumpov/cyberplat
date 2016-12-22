"use strict";

var assert = require("assert");


var Builder = require('./lib/builder');
var Crypto = require('./lib/crypto');
var Client = require('./lib/client');
var Parser = require('./lib/parser');
var Logger = require('./lib/logger');

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
    
    var parser = new Parser();

    var go = function(type, providerid, obj, callback) {

        var url = providers[providerid][type];

        var message = builder.buildMessage(type, obj);
        var signedMessage = crypto.sign(message);

        if (!signedMessage) {
            throw new Error('no sign message');
        }
        
        var str = signedMessage;    //signedMessage.replace(/\s/g, "+");

        log("signed message:", str);
        //log("trim:", trim(str));

        client.request(url, trim(str), function(response){

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
        limitStatus: limitStatus,
        fillStatus: fillStatus
    };
};

module.exports = Cyberplat;