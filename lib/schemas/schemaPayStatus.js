var Joi = require("joi");

var schemaPay = Joi.object().keys({    
    SESSION: Joi.string().required(),
    TRANSID: Joi.string().required(),
    ACCEPT_KEYS: Joi.string().allow("").default(""),
});

module.exports = schemaPay;