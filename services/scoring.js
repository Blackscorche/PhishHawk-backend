export function scorePhishingUrl({ domainAge, hasSSL, containsPhishingKeywords, virusTotalHit }) {
  let score = 0;
  
  // Enhanced scoring
  if (domainAge !== undefined && domainAge <= 7) score += 25;
  if (hasSSL === false) score += 20;
  if (containsPhishingKeywords === true) score += 30;
  if (virusTotalHit === true) score += 25;

  let risk = "Low";
  if (score >= 70) risk = "High";
  else if (score >= 40) risk = "Medium";

  return { score: Math.min(score, 100), risk };
}