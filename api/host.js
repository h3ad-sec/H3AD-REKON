import ShodanClient from 'shodan-client';

const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://h3ad-sec.github.io';

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': ALLOWED_ORIGIN,
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json',
  };
}

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).setHeaders(corsHeaders()).end();
  const headers = corsHeaders();
  Object.entries(headers).forEach(([k, v]) => res.setHeader(k, v));

  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'IP parameter required' });

  try {
    const SHODAN_KEY = process.env.SHODAN_KEY;
    const VT_KEY     = process.env.VT_KEY;
    const ABUSE_KEY  = process.env.ABUSEIPDB_KEY;

    // Shodan host lookup
    const shodanRes = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_KEY}`);
    const shodan = await shodanRes.json();

    // VirusTotal
    const vtRes = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
      headers: { 'x-apikey': VT_KEY }
    });
    const vtData = await vtRes.json();
    const vtStats = vtData?.data?.attributes?.last_analysis_stats || {};
    const vtVerdict = vtStats.malicious > 0 ? 'malicious' : vtStats.suspicious > 0 ? 'suspicious' : 'clean';

    // AbuseIPDB
    const abuseRes = await fetch(
      `https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`,
      { headers: { Key: ABUSE_KEY, Accept: 'application/json' } }
    );
    const abuseData = await abuseRes.json();
    const abuseScore = abuseData?.data?.abuseConfidenceScore ?? 0;
    const abuseVerdict = abuseScore > 50 ? 'malicious' : abuseScore > 10 ? 'suspicious' : 'clean';

    // Build clean Shodan response
    const shodanClean = {
      ip_str: shodan.ip_str,
      hostnames: shodan.hostnames || [],
      org: shodan.org,
      isp: shodan.isp,
      asn: shodan.asn,
      country_name: shodan.country_name,
      city: shodan.city,
      os: shodan.os,
      ports: shodan.ports || [],
      vulns: Object.keys(shodan.vulns || {}),
      last_update: shodan.last_update,
      ssl: extractSSL(shodan.data),
    };

    return res.status(200).json({
      shodan: shodanClean,
      vt: {
        verdict: vtVerdict,
        detections: vtStats.malicious || 0,
        total: Object.values(vtStats).reduce((a, b) => a + b, 0),
      },
      abuse: {
        verdict: abuseVerdict,
        score: abuseScore,
      },
    });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}

function extractSSL(data) {
  if (!data) return null;
  for (const item of data) {
    if (item.ssl) {
      const ssl = item.ssl;
      return {
        subject: ssl.cert?.subject?.CN || null,
        issuer: ssl.cert?.issuer?.O || null,
        expires: ssl.cert?.expires || null,
      };
    }
  }
  return null;
}
