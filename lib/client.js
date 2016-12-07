"use strict";

var unirest = require("unirest");

var Client = function (settings) {

    var payCheckUrl = "http://payment.cyberplat.ru/cgi-bin/es/es_pay_check.cgi";
    var payUrl = "http://payment.cyberplat.ru/cgi-bin/es/es_pay.cgi";
    var payStatusUrl = "http://payment.cyberplat.ru/cgi-bin/es/es_pay_status.cgi";

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

    var checkPayment = function (message, callback) {       
        unirest.post(payCheckUrl)
            .set('Content-Type', contentType)
            .set('User-Agent', userAgentString)
            .send('inputmessage=' + message)
            .end(function (response) {              
              callback(response);
            });
    };

    return {
        getUserAgentString: getUserAgentString,
        checkPayment: checkPayment
    };
};

module.exports = Client;