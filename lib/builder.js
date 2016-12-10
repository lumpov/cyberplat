"use strict";

var assert = require('assert');
var tracer = require('tracer');
var console = tracer.colorConsole({level:0});

var schemas = {
    payCheck: require('./schemas/schemaPayCheck'),
    pay: require('./schemas/schemaPay'),
    payStatus: require('./schemas/schemaPayStatus'),
    limitStatus: require('./schemas/schemaLimitStatus'),
    fillStatus: require('./schemas/schemaFillStatus'),
}

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

    var buildMessage = function (type, obj) {
        var message, schema = schemas[type];

        if (type !== 'payStatus') {       //payStatus не требует SD, AP, OP
            message = Object.assign({}, base, obj);
        } else {
            message = obj;
        }

        var result = schema.validate(message);

        if (result.error) {
            console.debug(result.error);
            return false;
        }

        return convert(result.value);
    };

    return {
        convert: convert,
        buildMessage: buildMessage        
    };
};

module.exports = Builder;