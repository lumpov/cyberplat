# Cyberplat 

nodejs module for interact with cyberplat.ru

## Prepare

compile libipriv.so for your platform [details: ./iprivpg]


## Install

> npm install cyberplat 


## Using 

`````javascript

var Cyberplat = require('cyberplat');
var moment = require('moment');
var randomstring = require("randomstring");

var cyberplat = new Cyberplat({
    crypto: {
        libPath: './libipriv/libipriv',    //path to file of lib libiriv
        secretKey: './secret/secret.key',  //path to secret.key
        secretPhrase: ''                   //secret password of secret key
    },
    settings: {
        SD: 17031,
        AP: 17032,
        OP: 17033
    },
    providers: {
        "227": {
            payCheckUrl: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay_check.cgi',
            payUrl: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay.cgi',
            payStatusUrl: 'https://service.cyberplat.ru/cgi-bin/es/es_pay_status.cgi'
        }
    }
    debug: true                             //false or true
});

var session = randomstring.generate(20);    //сессия не должна повторяться

var obj = {
    DATE: moment().format("DD.MM.YYYY HH:mm:ss"),
    AMOUNT: "1.00",
    AMOUNT_ALL: "1.00",
    COMMENT: "комментарий",
    NUMBER: "9135292926",
    SESSION: session
};

cyberplat.payCheck("227", obj, function(answer) {
    console.log("payCheck answer:", answer);
    
    if (answer.ERROR == "0" && answer.RESULT == "0") {
        cyberplat.payCheck("227", obj, function(answer) {
            console.log("pay answer:", answer);
        }
    }
});

`````