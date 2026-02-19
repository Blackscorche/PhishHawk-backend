export function scoreUrl(data) {
  let score = 0;
  if (data.domainAge < 7) score += 40;
  if (!data.hasSSL) score += 25;
  if (data.containsPhishingKeywords) score += 25;
  if (data.virusTotalHit) score += 10;
  return score;
}

export function getRiskLevel(score) {
  if (score >= 70) return "High";
  if (score >= 40) return "Medium";
  return "Low";
}
