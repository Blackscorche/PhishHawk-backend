import axios from 'axios';

const API_KEY = process.env.VIRUSTOTAL_API_KEY || process.env.VT_API_KEY;

export async function checkUrlWithVirusTotal(url, retries = 3) {
  if (!API_KEY) {
    return false;
  }

  const urlId = Buffer.from(url).toString('base64url').replace(/=+$/, '');
  const apiUrl = `https://www.virustotal.com/api/v3/urls/${urlId}`;

  for (let i = 0; i < retries; i++) {
    try {
      const res = await axios.get(apiUrl, {
        headers: { "x-apikey": API_KEY },
        timeout: 30000
      });
      
      const malicious = res.data?.data?.attributes?.last_analysis_stats?.malicious || 0;
      return malicious > 0;
    } catch (err) {
      if (err.response?.status === 404) {
        // URL not in database
        return false;
      }
      if (i === retries - 1) {
        console.error('VirusTotal API error:', err.message);
        return false;
      }
      // Wait before retry
      await new Promise(resolve => setTimeout(resolve, 1000 * (i + 1)));
    }
  }
  
  return false;
}