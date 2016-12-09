"use strict";

var assert = require('assert');
var tracer = require('tracer');
var console = tracer.colorConsole({level:0});

var schemaPayCheck = require('./schemes/schemaPayCheck');

var Builder = function (settings) {

    //@todo добавить конверт в 1251
    
    if (settings.debug) {
        tracer.setLevel('debug');
    } else {
        tracer.setLevel('error');
    }

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
        console.debug("converted message:", arr.join(DELIMETER));
        return arr.join(DELIMETER);
    };

    var buildPayCheckMessage = function (obj) {
        var result = schemaPayCheck.validate(obj);        

        if (result.error) {
            console.debug(result.error);
            return false;
        }

        var message = result.value;
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