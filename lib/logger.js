"use strict";

var Logger = function () {

	var log = function () {
		var time = (new Date()).toString();
        console.log(time, arguments[0], arguments[1]);
    };

    return {
        log: log
    }
};

module.exports = Logger;