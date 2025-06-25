import { body, validationResult } from "express-validator";

export const phishingValidationRules = [
  body("url").isURL().withMessage("Invalid URL"),
  body("domainAge").isInt({ min: 0 }),
  body("hasSSL").isBoolean(),
  body("containsPhishingKeywords").isBoolean()
];

export const validatePhishingRequest = (req, res, next) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
  next();
};
