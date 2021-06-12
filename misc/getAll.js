

var cheerio = require('cheerio');
var unirest = require('unirest');
var fs = require('fs');

var pp = {};
var baseUrl = 'https://service.cyberplat.ru';
fs.readFile('./source.json', function (err, content) {

    var providers = JSON.parse(content);
    console.log('Count:', providers.length);

    var promises = providers.map(function(provider) {
        return new Promise(function(resolve, reject){   

            console.log(provider);

            var w = [];
            var req = unirest.get(baseUrl + provider.url);

            req.end(function(response) {
                if (response.body) {
                    var $ = cheerio.load(response.body);

                    $(".cll td.tit").each(function(i, el) {
                        w.push($(el).text());
                    });

                    var p1 = Object.assign({}, provider, {
                        url: baseUrl + provider.url,
                        payCheck: w[1],
                        pay: w[3],
                        payStatus: w[5]
                    });

                    pp[provider.code] = p1;
                    console.log('push', p1);
                }
                resolve(p1);

            });
        });
        
    });

    Promise.all(promises).then(function(values){
        console.log("Count:", pp.length);
        fs.writeFile('./providers.json', JSON.stringify(pp, null, "  "), console.log);
        //console.log(values);    
    }, function(reason){
        console.log(reason);
    });
    
});

