# Cyberplat 

nodejs модуль для проведения платежей через сервис cyberplat.ru

[![Build Status](https://travis-ci.org/antirek/cyberplat.svg?branch=master)](https://travis-ci.org/antirek/cyberplat)

## Подготовка

Для проведения платежей необходимо осуществлять криптографическую подпись сообщения. Для этого используется libipriv. 

## Установка

> npm install  nbind autogypi node-gyp
> npm run install
> npm install
> npm run test
> npm install cyberplat 

## Пример использования

`````javascript

var Cyberplat = require('cyberplat');
var moment = require('moment');
var randomstring = require("randomstring");

var cyberplat = new Cyberplat({
    crypto: {
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
            payCheck: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay_check.cgi',
            pay: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay.cgi',
            payStatus: 'https://service.cyberplat.ru/cgi-bin/es/es_pay_status.cgi'
        }
    },
    logger: console                  
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
        cyberplat.pay("227", obj, function(answer) {
            console.log("pay answer:", answer);

        }
    }
});

`````

### Пояснения к примеру

1. Для проведения платежей необходимо установить настройки модуля.

2. В настройках есть несколько логических секций: crypto, settings, providers, logger.

3. В секции crypto указываются необходимые для криптографической подписи параметры: путь к модулю libipriv.so, путь к секретному ключу, секретная фраза. Секретный ключ и секретная фраза получаются в сервисе cyberplat.ru.

4. В секции settings указываются настройки SD, AP, OP - коды контрагента, точки приема и оператора точки приема. Затем эти параметры используются во всех сообщениях для проведения платежей.

5. В секции providers указываются адреса для каждого типа запросов к сервису cyberplat.ru.

6. В секции logger передается объект логгирования (например, console)

7. Типы запросов к сервису cyberplat.ru:

- а. payCheck - запрос на получение разрешения на платеж

- б. pay - запрос на платеж

- в. payStatus - запрос на получение статуса платежа


* В соответствии с [Руководством по программному взаимодействию с системой "Cyberplat"](http://www.cyberplat.ru/download/API_CyberPlat.pdf), пункты 2.2, 2.3, 2.4


8. Для каждого типа запроса в каждом провайдере в секции providers должен быть соответствующий url. Например: 

`````javascript

"227": {
    payCheck: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay_check.cgi',
    pay: 'https://service.cyberplat.ru/cgi-bin/t2/t2_pay.cgi',
    payStatus: 'https://service.cyberplat.ru/cgi-bin/es/es_pay_status.cgi'
}

`````

* Пример списка провайдеров: ./misc/providers.json, получен из [списка провайдеров Cyberplat](https://service.cyberplat.ru/cgi-bin/view_stat.utf/help.cgi)

9. Затем при вызове запроса указывается код провайдера, модуль cyberplat берет соответствующий url и согласно порядка, описанному в пункте 3 [Руководства по программному взаимодействию с системой "Cyberplat"](http://www.cyberplat.ru/download/API_CyberPlat.pdf)


## Поддержка

Вопросы? Баги? 

email serge.dmitriev@gmail.com