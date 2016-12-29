"use strict";

var assert = require('assert');


var schemas = {
    payCheck: require('./schemas/schemaPayCheck'),
    pay: require('./schemas/schemaPay'),
    payStatus: require('./schemas/schemaPayStatus'),
    limitStatus: require('./schemas/schemaLimitStatus'),
    fillStatus: require('./schemas/schemaFillStatus'),
}

var Builder = function (settings = {}, logger) {

    var log = function() {
        if (logger) {
            logger.log(arguments[0], arguments[1]);
        }
    };
    
    var base = {
        SD: settings.SD,
        AP: settings.AP,
        OP: settings.OP
    };

    var DELIMETER = "\r\n";

    var obj2str = function (obj) {
        var arr = Object.keys(obj).map(function(key){
            return key + "=" + obj[key];
        });
        log("converted message:", arr.join(DELIMETER));
        return arr.join(DELIMETER);
    };

    var buildMessage = function (type, obj) {
        var message, schema = schemas[type];

        if (type !== 'payStatus') {       //payStatus не требует SD, AP, OP
            message = Object.assign({}, base, obj);
        } else {
            message = obj;
        }

        var result = schema.validate(message, {allowUnknown: true});

        if (result.error) {
            log(result.error);
            return false;
        }

        return obj2str(result.value);
    };

    return {
        obj2str: obj2str,
        buildMessage: buildMessage        
    };
};

module.exports = Builder;