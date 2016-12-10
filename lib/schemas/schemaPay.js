var Joi = require("joi");

var schemaPay = Joi.object().keys({
    SD: Joi.number().required(),
    AP: Joi.number().required(),
    OP: Joi.number().required(),
    DATE: Joi.string().required(),
    NUMBER: Joi.string().allow("").default("").max(20),
    ACCOUNT: Joi.string().allow("").default(""),
    SESSION: Joi.string().required(),
    AMOUNT: Joi.string().required(),
    AMOUNT_ALL: Joi.string().required(),
    PAY_TOOL: Joi.number().integer().default(0).valid(0,1,2),
    TERM_ID: Joi.string().required(),
    ACCEPT_KEYS: Joi.string().allow("").default(""),
    NO_ROUTE: Joi.number().integer().default(0).valid(0,1),
    RRN: Joi.string().allow("").default("")
});

module.exports = schemaPay;