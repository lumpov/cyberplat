"use strict";

var Builder = require('./lib/builder');
var Crypto = require('./lib/crypto');
var Client = require('./lib/client');
var Parser = require('./lib/parser');

var Cyberplat = function (ops) {

    if (ops.debug) {
        Object.assign(ops.crypto, {debug: true});
        Object.assign(ops.settings, {debug: true});
    }

    var builder = new Builder(ops.settings);
    var crypto = new Crypto(ops.crypto);
    var client = new Client(ops.settings);
    
    var parser = new Parser();

    var go = function(type, obj, callback) {
        var message = builder.buildMessage(type, obj);
        var signedMessage = crypto.sign(message);
        client.request(type, signedMessage, function(response){

            // здесь добавить верификацию полученного сообщения
            console.log(response.body);
            var answer = parser.parse(response.body);
            console.log(answer);
            callback(answer.error, answer.object);
        });
    };

    var payCheck = function (obj, callback) {
        console.log("ops.crypto", ops.crypto);
        go('payCheck', obj, callback);
    };

    var pay = function (obj, callback) {
        go('pay', obj, callback);
    };

    var payStatus = function (obj, callback) {
        go('payStatus', obj, callback);
    };

    var limitStatus = function (obj, callback) {
        go('limitStatus', obj, callback);
    };

    var fillStatus = function (obj, callback) {
        go('fillStatus', obj, callback);
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