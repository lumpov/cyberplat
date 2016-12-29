var Joi = require("joi");

var schemaFillStatus = Joi.object().keys({
	SD: Joi.number().required(),
    AP: Joi.number().required(),
    OP: Joi.number().required(),
    ON_DATE: Joi.string().required().min(10).max(10),
    SESSION: Joi.string().required(),
    ACCEPT_KEYS: Joi.string().allow("").default(""),
});

module.exports = schemaFillStatus;