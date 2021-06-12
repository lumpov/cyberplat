var assert = require('assert');
var randomstring = require('randomstring');
var moment = require('moment');
var fs = require('fs')


var Cyberplat = require('../index')
var Parser = require('../lib/parser');


describe("Cyberplat local", function() {

    var http = require('http');

    var handle = function (req, res) {
        var message = fs.readFileSync('./tests/message.txt', 'utf8');
        res.end(message);
    };

    var port = 8998;
    var server = http.createServer(handle);

    server.listen(port);

    it("check create", function(done) {
        var cyberplat = new Cyberplat({
            crypto: {
                secretKey: './tests/secret.key',
                secretPhrase: '1111111111',   //password
	            publicKey: "./tests/pubkeys.key",
	            publicSerial: 64182       // serial number of cyberplat key
            },
            settings: {
                SD: 17031,
                AP: 17032,
                OP: 17034
            },
            providers: {
                "local": {
                    payCheck: 'http://localhost:' + port + '/payCheck',
                    pay: 'http://localhost:' + port + '/pay',
                    payStatus: 'http://localhost:' + port + '/payStatus',
                }
            }
        });

        var session = randomstring.generate(7);

        var obj = {
            DATE: moment().format("DD.MM.YYYY HH:mm:ss"),
            AMOUNT: "1.00",
            AMOUNT_ALL: "1.00",
            COMMENT: "mimi",
            TERM_ID: "1",
            NUMBER: "8888888888",
            REQ_TYPE: 0,
            SESSION: session
        };

        cyberplat.payCheck("local", obj, function(answer) {
            //console.log("payCheck answer", answer);
            
            assert.equal(answer.ERROR, "1");
            assert.equal(answer.RESULT, "1");

            cyberplat.pay("local", obj, function(answer) {
                //console.log("pay answer", answer)
                
                assert.equal(answer.ERROR, "1");
                assert.equal(answer.RESULT, "1");
            
                done();
            })

        });


    }); 
    
});
