"use strict";

var Crypto = require('./lib/crypto');
var Client = require('./lib/client');
var Builder = require('./lib/builder');

var Cyberplat = function (ops) {
    var crypto = new Crypto(ops.crypto);
    var client = new Client(ops.settings);
    var builder = new Builder(ops.settings);

    return {

    };
};

module.exports = Cyberplat;