"use strict";

var unirest = require("unirest");
var tracer = require('tracer');
var urlencode = require('urlencode');
var assert = require('assert');

var Client = function (settings, logger) {
    assert(settings);
    assert(settings.SD);
    assert(settings.AP);
    assert(settings.OP);

    var log = function() {
        if (logger) {
            logger.log(arguments[0], arguments[1]);
        }
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

    var request = function (url, message, callback) {
        log('length:', message.length);
        //message = message.toString().replace(" ", "+");
        //var urlencoded = urlencode(message)
        var urlencoded = urlencode(message); //.replace(/\%00/g,"");  //удаляем %00 на конце строки

        log('request:', url)
        log('urlencoded:', urlencoded);
        unirest.post(url)
            .set('Content-Type', contentType)
            .set('User-Agent', userAgentString)
            .send('inputmessage=' + urlencoded)
            .end(function (response) {
              log('response body:', response.body);
              callback(response);
            });
    };    

    return {
        getUserAgentString: getUserAgentString,
        request: request
    };
};

module.exports = Client;