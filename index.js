"use strict";

var Crypto = require('./lib/crypto');
var Client = require('./lib/client');
var Builder = require('./lib/builder');

var Cyberplat = function (ops) {
    var crypto = new Crypto(ops.crypto);
    var client = new Client(ops.settings);
    var builder = new Builder(ops.settings);

    var go = function(type, obj, callback) {
        var message = builder.buildMessage(type, obj);
        var signedMessage = crypto.sign(message);
        client.request(type, signedMessage, callback);
    };

    var payCheck = function (obj, callback) {
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