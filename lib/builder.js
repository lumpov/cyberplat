"use strict";
var assert = require('assert');
var Joi = require('joi');
var tracer = require('tracer');
var console = tracer.colorConsole({level:0});

var schema = Joi.object().keys({
    DATE: Joi.string().required(),
    NUMBER: Joi.string().allow("").default(""),
    SESSION: Joi.string().required(),
    AMOUNT: Joi.string().required()
});


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
        console.debug(arr.join(DELIMETER));
        return arr.join(DELIMETER);
    };

    var buildPayCheckMessage = function(obj) {
        assert(obj.DATE);
        assert(obj.SESSION);
        assert(obj.AMOUNT);

        const result = schema.validate(obj);
        console.debug(result.err, result.value);

        var message = result.value; //Object.assign({}, obj);
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