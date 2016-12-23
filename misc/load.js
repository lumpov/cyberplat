/*

https://service.cyberplat.ru/cgi-bin/view_stat.utf/help.cgi


*/

var cheerio = require('cheerio');
var unirest = require('unirest');
var fs = require('fs');

var Request = unirest.get('https://service.cyberplat.ru/cgi-bin/view_stat.utf/help.cgi');

var arr = [];
Request.end(function(response) {
	//console.log(response.body);

	var $ = cheerio.load(response.body);

	$('h2.hp').each(function(index, element){
		//console.log("----", element);
		//if (index == 1) {
			console.log(index);
			var onclick = element.attribs.onclick;
			var url = onclick.split('\'')[1];
			//console.log(url);

			var text = $(element).text();
			var name = text.trim();
			var code = name.split('(').slice(-1).pop().replace(')','');

			var j = {
				name: name,
				code: code,
				url: url
			}
			console.log(name, code);
			arr.push(j);			
		//}
	});

	console.log("Count:", arr.length);
	fs.writeFile('./source.json', JSON.stringify(arr, null, "  "), console.log);
	
});

//

