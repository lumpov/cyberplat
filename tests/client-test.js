var assert = require('assert');
var Client = require('../lib/client')

describe("Client", function() {
    
    it("check set user agent string", function(done) {
        var client = new Client({
            AP: 1,
            SD: 2,
            OP: 3
        });

        var expectedUserAgentString = "User-Agent: Cyberplat.js ver. 0.1, SD: 2, AP: 1, OP: 3";
        assert.equal(client.getUserAgentString(), expectedUserAgentString);
        //require('request').debug = true;

        var str = "0000037901SM000001180000011800000125%0D%0Aapi17032++++++++++++00017033%0D%0A++++++++++++++++++++00000000%0D%0ABEGIN%0D%0ASD%3D17031%0D%0AAP%3D17032%0D%0AOP%3D17034%0D%0ASESSION%3D4b34d1d400000cb80029%0D%0ANUMBER%3D8888888888%0D%0AAMOUNT%3D11%2E00%0D%0AAMOUNT%5FALL%3D11%0D%0ACOMMENT%3D%0D%0A%0D%0AEND%0D%0ABEGIN+SIGNATURE%0D%0AiQBRAwkBAABCiUs00dQBATG5AgDHdZ6RYHykL46QbaAvnHYaY4p0pDjgjO4K1Iyj%0D%0AfSBSvCRpS%2F0EYO9NspuyLeANEQQkkGE%2F37gUxiPqzAgStXjpsAHH%0D%0A%3DvSgb%0D%0AEND+SIGNATURE";

        client.payCheck(str, function(response) {
            console.log("response.body", response.body);
            done();
        });
    }); 
    
});