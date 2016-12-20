
var Cyberplat = require('./index');
var moment = require('moment');

var cyberplat = new Cyberplat({
    crypto: {
        libPath: '/usr/lib/libipriv/libipriv',     //path to file of lib libiriv
        secretKey: '/var/secretplace/secret.key',  //path to secret.key
        secretPhrase: 'secretPassword'             //secret password of secret key
    },
    settings: {
        SD: 17031,
        AP: 17032,
        OP: 17033,
    },
    debug: false   //or true
});

var obj = {
    DATE: moment().format("DD.MM.YYYY HH:mm:ss"),
    AMOUNT: "1.00",
    AMOUNT_ALL: "1.00",
    COMMENT: "comment",
    TERM_ID: "1",
    NUMBER: "9135292926",
    REQ_TYPE: 0,
    SESSION: "4b34d1d400000cb80029"
};

cyberplat.payCheck("227", obj, function(err, answer) {
    console.log(answer);
    done();
});


