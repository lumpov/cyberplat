"use strict";

var assert = require('assert');
var tracer = require('tracer');
var console = tracer.colorConsole({level:0});

var schemaPayCheck = require('./schemes/schemaPayCheck');
var schemaPay = require('./schemes/schemaPay');
var schemaPayStatus = require('./schemes/schemaPayStatus');

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

    var buildMessage = function (obj, schema) {
        var result = schema.validate(obj);

        if (result.error) {
            console.debug(result.error);
            return false;
        }

        return convert(result.value);
    };

    var buildPayCheckMessage = function (obj) {
        var message = Object.assign({}, base, obj);
        return buildMessage(message, schemaPayCheck);
    };

    var buildPayMessage = function (obj) {
        var message = Object.assign({}, base, obj);
        return buildMessage(message, schemaPay);
    };

    var buildPayStatusMessage = function (obj) {
        return buildMessage(obj, schemaPayStatus);
    };


    return {
        convert: convert,
        //buildMessage: buildMessage,
        buildPayCheckMessage: buildPayCheckMessage,
        buildPayMessage: buildPayMessage,
        buildPayStatusMessage: buildPayStatusMessage
    };
};

module.exports = Builder;