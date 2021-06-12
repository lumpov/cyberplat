

var Iconv  = require('iconv').Iconv;
var Crypto = require('../lib/crypto');

describe("Encoding", function() {

var iconvUtf8ToWin1251 = new Iconv('UTF-8', 'windows-1251');
var iconvWin1251ToUtf8 = new Iconv('windows-1251', 'UTF-8');

var ops_crypto = {
	secretKey: './tests/secret.key',  //path to secret.key
	secretPhrase: '1111111111',       //secret password of secret key
	publicKey: "./tests/pubkeys.key",
	publicSerial: 64182               //serial number of cyberplat key
}

var crypto = new Crypto(ops_crypto, console);

var message = "Сообщение, которое требуется подписать";
console.log ('message', message);
var encodedMessageToWin1251 = iconvUtf8ToWin1251.convert(message);
var signedMessage = crypto.sign(encodedMessageToWin1251);

if (!signedMessage) {
    throw new Error('no sign message');
}

var str = iconvWin1251ToUtf8.convert(signedMessage).toString();
console.log ('signed message in utf8', str);

});

