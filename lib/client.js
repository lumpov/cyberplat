"use strict";

var unirest = require("unirest");
var tracer = require('tracer');
var console = tracer.colorConsole({level:0});

var Client = function (settings) {

    if (settings.debug) {
        tracer.setLevel('debug');
    } else {
        tracer.setLevel('error');
    }

    var payCheckUrl = "https://payment.cyberplat.ru/cgi-bin/es/es_pay_check.cgi";
    var payUrl = "https://payment.cyberplat.ru/cgi-bin/es/es_pay.cgi";
    var payStatusUrl = "https://payment.cyberplat.ru/cgi-bin/es/es_pay_status.cgi";
    var limitStatus = "https://service.cyberplat.ru/cgi-bin/status/get_rest.cgi";
    var fillStatus = "https://service.cyberplat.ru/cgi-bin/misc/refill_info.cgi";

    var userAgentString = [
        "User-Agent: Cyberplat.js ver. 0.1",
        "SD: " + settings.SD,
        "AP: " + settings.AP,
        "OP: " + settings.OP
        ].join(", ");

    var contentType = "application/x-www-form-urlencoded";

    var getUserAgentString = function () {
        return userAgentString;
    };

    var request = function (url, message, callback) {
        console.debug('request', url, message);
        unirest.post(url)
            .set('Content-Type', contentType)
            .set('User-Agent', userAgentString)
            .send('inputmessage=' + message)
            .end(function (response) {
              callback(response);
            });
    };

    var payCheck = function(message, callback) {
        request(payCheckUrl, message, callback);
    };

    var pay = function(message, callback) {
        request(payUrl, message, callback);
    };

    var payStatus = function(message, callback) {
        request(payStatusUrl, message, callback);
    };

    var limitStatus = function(message, callback) {
        request(limitStatusUrl, message, callback);
    };

    var fillStatus = function(message, callback) {
        request(fillStatusUrl, message, callback);
    };

    return {
        getUserAgentString: getUserAgentString,
        payCheck: payCheck,
        pay: pay,
        payStatus: payStatus,
        limitStatus: limitStatus,
        fillStatus: fillStatus
    };
};

module.exports = Client;