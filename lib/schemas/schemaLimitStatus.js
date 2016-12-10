var Joi = require("joi");

var schemaLimitStatus = Joi.object().keys({
	SD: Joi.number().required(),
    AP: Joi.number().required(),
    OP: Joi.number().required(),
    SESSION: Joi.string().required(),
    ACCEPT_KEYS: Joi.string().required()
});

module.exports = schemaLimitStatus;