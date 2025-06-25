export function scorePhishingUrl({ domainAge, hasSSL, containsPhishingKeywords, virusTotalHit }) {
  let score = 0;
  if (domainAge <= 7) score += 1;
  if (!hasSSL) score += 1;
  if (containsPhishingKeywords) score += 2;
  if (virusTotalHit) score += 3;

  let risk = "Low";
  if (score >= 3) risk = "Medium";
  if (score >= 5) risk = "High";

  return { score, risk };
}
