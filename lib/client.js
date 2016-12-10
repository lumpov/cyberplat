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

    var urls = {
        payCheck: settings.payCheckUrl || "https://payment.cyberplat.ru/cgi-bin/es/es_pay_check.cgi",
        pay: settings.payUrl || "https://payment.cyberplat.ru/cgi-bin/es/es_pay.cgi",
        payStatus: settings.payStatusUrl || "https://payment.cyberplat.ru/cgi-bin/es/es_pay_status.cgi",
        limitStatus: settings.limitStatusUrl || "https://service.cyberplat.ru/cgi-bin/status/get_rest.cgi",
        fillStatus: settings.fillStatusUrl || "https://service.cyberplat.ru/cgi-bin/misc/refill_info.cgi"
    };

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

    var request = function (type, message, callback) {
        var url = urls[type];
        console.debug('request:', url, message);
        unirest.post(url)
            .set('Content-Type', contentType)
            .set('User-Agent', userAgentString)
            .send('inputmessage=' + message)
            .end(function (response) {
              console.debug('response body:', response.body);
              callback(response);
            });
    };    

    return {
        getUserAgentString: getUserAgentString,
        request: request
    };
};

module.exports = Client;