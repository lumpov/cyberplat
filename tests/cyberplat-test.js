var assert = require('assert');
var Cyberplat = require('../index')
var moment = require('moment');

describe("Cyberplat", function() {

    it("check create", function(done) {
        var cyberplat = new Cyberplat({
            crypto: {
                libPath: './tests/libipriv',
                secretKey: './tests/secret.key',
                secretPhrase: '1111111111'   //password
            },
            settings: {
                AP: 1,
                SD: 2,
                OP: 3,
                useHTTPS: false
            },
            debug: false
        });

        var obj = {
            DATE: "12",
            SESSION: 'session',
            AMOUNT: "1.00",
            AMOUNT_ALL: "1.00",
            TERM_ID: "1",
            NUMBER: "1212"
        };

        cyberplat.payCheck("227", obj, function(err, answer) {
            console.log(answer);
            done();
        });

    }); 

    it("check create", function(done) {
        var cyberplat = new Cyberplat({
            crypto: {
                libPath: './tests/libipriv',
                secretKey: './tests/secret.key',
                secretPhrase: '1111111111'   //password
            },
            settings: {
                SD: 17031,
                AP: 17032,
                OP: 17034,
                useHTTPS: false
            },
            debug: true
        });

        var obj = {
            DATE: moment().format("DD.MM.YYYY HH:mm:ss"),
            AMOUNT: "1.00",
            AMOUNT_ALL: "1.00",
            COMMENT: "вася",
            TERM_ID: "1",
            NUMBER: "8888888888",
            REQ_TYPE: 1,
            SESSION: "4b34d1d400000cb80029"
        };

        cyberplat.payCheck("227", obj, function(err, answer) {
            console.log(answer);
            done();
        });

    }); 
    
});