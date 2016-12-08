"use strict";
var assert = require('assert');

var Builder = function (settings) {

    var base = {
        SD: settings.SD,
        AP: settings.AP,
        OP: settings.OP
    };

    var DELIMETER = "\r\n";

    var convert = function (obj) {
        var arr = Object.keys(obj).map(function(key){
            return key + "=" + obj[key];
        });
        return arr.join(DELIMETER);
    };

    var buildPayCheckMessage = function(obj) {
        assert(obj.DATE);
        assert(obj.SESSION);
        assert(obj.AMOUNT);

        var message = Object.assign({}, obj);
        message.SD = base.SD;
        message.AP = base.AP;
        message.OP = base.OP;

        return convert(message);
    };



    return {
        convert: convert,
        buildPayCheckMessage: buildPayCheckMessage
    };
};

module.exports = Builder;