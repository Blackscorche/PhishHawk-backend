import rateLimit from "express-rate-limit";

export const phishingRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { error: "Too many requests from this IP, try again later." }
});
