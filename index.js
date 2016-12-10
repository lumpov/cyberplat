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
    }

    var payCheck = function (obj, callback) {
        go('payCheck', obj, callback);
    };

    return {

    };
};

module.exports = Cyberplat;