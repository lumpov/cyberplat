var assert = require('assert');
var Client = require('../lib/client');
var Logger = require('../lib/logger');

var unirest = require('unirest');

describe("Client", function() {

    var client = new Client({
        AP: 1,
        SD: 2,
        OP: 3,
        debug: true
    });

    it("check set user agent string", function() {
        var expectedUserAgentString = "User-Agent: Cyberplat.js ver. 0.1, SD: 2, AP: 1, OP: 3";
        assert.equal(client.getUserAgentString(), expectedUserAgentString);        
    }); 
    
    it("check", function(done) {
        var str = "name=Привет!";

        client.request("https://service.cyberplat.ru/cgi-bin/t2/t2_pay_check.cgi", str, function(response) {
            console.log("response.body", response.body);
            done();
        });
    })
});

describe("Client with server", function() {

    it("run test simple http server", function(done){
        var http = require('http');

        var handle = function (req, res) {
            res.end("good message");
            //done();
        };

        var port = 8999;
        var server = http.createServer(handle);

        server.listen(port, function(){
            //console.log("start server")
        });

        // make request
        var url = "http://localhost:8999";

        unirest
            .get(url)
            .end(function(response){
                //console.log(response.body);
                assert.equal(response.body, "good message");
                done();
            });
    });
});