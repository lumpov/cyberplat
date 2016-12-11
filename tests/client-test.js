var assert = require('assert');
var Client = require('../lib/client')


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

        client.request('payCheck', str, function(response) {
            console.log("response.body", response.body);
            done();
        });
    })
});