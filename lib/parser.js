"use strict";

var tracer = require('tracer');
var console = tracer.colorConsole({level:0});

var Parser = function (settings = {}) {

    if (settings.debug) {
        tracer.setLevel('debug');
    } else {
        tracer.setLevel('error');
    }

    var strings2obj = function(message){
        var DELIMITER = "\r\n";
        var strings = message.split(DELIMITER);
        var pass = false;
        
        console.debug("splitted message:", strings);

        var obj = {};
        var counter = 0;
        for (var i = 0; i < strings.length; i++) {
            if (strings[i] === 'END') {   // 2. нашли строку конец, со следующей не будем парсить
                pass = false;
            }

            if (pass && strings[i] !== '') {   // 3. пока pass включен, парсим 
                var tmp = strings[i].split("=");
                obj[tmp[0]] = tmp[1];
                counter++;            // счетчик на случай если между BEGIN и END нет key=value
            }

            if (strings[i] === 'BEGIN') {  // 1. нашли строку начало, со следующей будем парсить
                pass = true;
            }
        };

        console.debug("object:", obj);
        return (counter > 0) ? obj : null;
    };


    var parse = function(message) {
        return {
            error: null,
            body: message.toString(),
            object: strings2obj(message.toString())
        }
    };

    return {
        parse: parse
    };
};

module.exports = Parser;