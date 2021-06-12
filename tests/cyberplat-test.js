var assert = require('assert');
var Cyberplat = require('../index')
var moment = require('moment');

describe("Cyberplat", function() {

    it("check create", function(done) {
        var cyberplat = new Cyberplat({
            crypto: {
                secretKey: './tests/secret.key',
                secretPhrase: '1111111111',   //password
                publicKey: './tests/pubkeys.key',
                publicSerial: 64182       // serial number of cyberplat key
            },
            settings: {
                AP: 1,
                SD: 2,
                OP: 3,
            },
            providers: {
                "227": {
                    payCheck: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay_check.cgi',
                    pay: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay.cgi',
                    payStatus: 'https://service.cyberplat.ru/cgi-bin/es/es_pay_status.cgi'
                },
                "180": {
                    payCheck: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay_check.cgi',
                    pay: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay.cgi',
                    payStatus: 'https://service.cyberplat.ru/cgi-bin/es/es_pay_status.cgi'
                }
            }
        });

        var obj = {
            DATE: "12",
            SESSION: 'session',
            AMOUNT: "1.00",
            AMOUNT_ALL: "1.00",
            TERM_ID: "1",
            NUMBER: "1212"
        };

        cyberplat.payCheck("227", obj, function(answer) {
            assert(answer);
            assert.equal(answer.ERROR,"6");
            assert.equal(answer.RESULT,"1");
            done();
        });

    }); 

    it("check create", function(done) {
        var cyberplat = new Cyberplat({
            crypto: {
                libPath: './tests/libipriv',
                secretKey: './tests/secret.key',
                secretPhrase: '1111111111',   //password
	            publicKey: "./tests/pubkeys.key",
	            publicSerial: 64182       // serial number of cyberplat key
            },
            settings: {
                SD: 17031,
                AP: 17032,
                OP: 17034,
            },
            providers: {
                "2": {
                    payCheck: 'https://ru-demo.cyberplat.com/cgi-bin/es/es_pay_check.cgi',
                    pay: 'https://ru-demo.cyberplat.com/cgi-bin/es/es_pay.cgi',
                    payStatus: 'https://ru-demo.cyberplat.com/cgi-bin/es/es_pay_status.cgi'
                },
                "227": {
                    payCheck: 'https://ru-demo.cyberplat.com/cgi-bin/es/es_pay_check.cgi',
                    pay: 'https://ru-demo.cyberplat.com/cgi-bin/es/es_pay.cgi',
                    payStatus: 'https://ru-demo.cyberplat.com/cgi-bin/es/es_pay_status.cgi'
                }
            }
        });

        var obj = {
            DATE: moment().format("DD.MM.YYYY HH:mm:ss"),
            AMOUNT: "1.00",
            AMOUNT_ALL: "1.00",
            COMMENT: "mimimi",
            TERM_ID: "1",
            NUMBER: "8888888888",
            REQ_TYPE: 0,
            SESSION: cyberplat.generateNewSession()
        };

        cyberplat.payCheck("227", obj, function(answer) {
            console.log("answer 227:", answer);
            done();
        });

    }); 
    
});