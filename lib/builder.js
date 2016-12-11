"use strict";

var assert = require('assert');
var tracer = require('tracer');
var console = tracer.colorConsole({level:0});
var iconv = require('iconv-lite');

var schemas = {
    payCheck: require('./schemas/schemaPayCheck'),
    pay: require('./schemas/schemaPay'),
    payStatus: require('./schemas/schemaPayStatus'),
    limitStatus: require('./schemas/schemaLimitStatus'),
    fillStatus: require('./schemas/schemaFillStatus'),
}

var Builder = function (settings = {}) {
    var convert2win1251 = settings.convert2win1251 || true;
    
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

    var convertEncoding = function (strInUTF8) {        
        var converted = iconv.encode(strInUTF8, 'win1251');
        console.debug('encoded:', converted);
        return converted.toString();
    }

    var obj2str = function (obj) {
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

        return convert2win1251 ? convertEncoding(obj2str(result.value)) :
                                 obj2str(result.value);
    };

    return {
        obj2str: obj2str,
        convertEncoding: convertEncoding,
        buildMessage: buildMessage        
    };
};

module.exports = Builder;