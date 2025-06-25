import fetch from "node-fetch";
const API_KEY = process.env.VT_API_KEY;

export async function checkUrlWithVirusTotal(url, retries = 3) {
  const base64Url = Buffer.from(url).toString("base64").replace(/=+$/, "");
  const apiUrl = `https://www.virustotal.com/api/v3/urls/${base64Url}`;

  for (let i = 0; i < retries; i++) {
    try {
      const res = await fetch(apiUrl, {
        headers: { "x-apikey": API_KEY }
      });
      const data = await res.json();
      const malicious = data.data?.attributes?.last_analysis_stats?.malicious || 0;
      return malicious > 0;
    } catch (err) {
      if (i === retries - 1) return false;
    }
  }
}
