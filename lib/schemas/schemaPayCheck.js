var Joi = require("joi");

var schemaPayCheck = Joi.object().keys({
    SD: Joi.number().required(),
    AP: Joi.number().required(),
    OP: Joi.number().required(),
    DATE: Joi.string().required(),
    NUMBER: Joi.string().allow("").default("").max(20),
    ACCOUNT: Joi.string().allow("").default(""),
    SESSION: Joi.string().required(),
    AMOUNT: Joi.string().required(),
    AMOUNT_ALL: Joi.string().required(),
    REQ_TYPE: Joi.number().integer().default(0).valid(0,1),
    PAY_TOOL: Joi.number().integer().default(0).valid(0,1,2),
    TERM_ID: Joi.string(),
    COMMENT: Joi.string().allow("").default("").min(0).max(64),
    ACCEPT_KEYS: Joi.string().allow("").default(""),
    NO_ROUTE: Joi.number().integer().default(0).valid(0,1)
});

module.exports = schemaPayCheck;