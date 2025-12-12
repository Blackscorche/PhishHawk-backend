import { body, validationResult } from "express-validator";

export const phishingValidationRules = [
  body("url")
    .notEmpty().withMessage("URL is required")
    .isURL({ 
      require_protocol: false, // Allow URLs without protocol
      require_valid_protocol: true,
      protocols: ['http', 'https']
    })
    .withMessage("Invalid URL format"),
  body("source").optional().isIn([
    'manual', 'twitter', 'rss', 'email', 'bulk_import', 'api', 'urlhaus',
    'sms', 'social', 'other' // Additional sources from frontend
  ]).withMessage("Invalid source"),
  body("priority").optional().isIn(['low', 'medium', 'high', 'critical']).withMessage("Invalid priority")
];

export const validatePhishingRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    const errorMessages = errors.array().map(err => err.msg || err.message);
    return res.status(400).json({ 
      success: false,
      error: 'Validation failed',
      message: errorMessages.join(', '),
      errors: errors.array() 
    });
  }
  next();
};
