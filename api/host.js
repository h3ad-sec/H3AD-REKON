export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowed = process.env.ALLOWED_ORIGIN || '';
  res.setHeader('Access-Control-Allow-Origin', allowed.includes(origin) ? origin : allowed.split(',')[0].trim());
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const { ip } = req.query;
  if (!ip) return res.status(400).json({ error: 'IP parameter required' });

  const SHODAN_KEY  = process.env.SHODAN_KEY;
  const VT_KEY      = process.env.VT_KEY;
  const ABUSE_KEY   = process.env.ABUSEIPDB_KEY;

  try {
    // Shodan
    const shodanRes = await fetch(`https://api.shodan.io/shodan/host/${ip}?key=${SHODAN_KEY}`);
    if (!shodanRes.ok) return res.status(500).json({ error: `Shodan error: ${shodanRes.status}` });
    const shodan = await shodanRes.json();

    // VirusTotal
    let vt = { verdict: 'unknown', detections: 0, total: 0 };
    try {
      const vtRes = await fetch(`https://www.virustotal.com/api/v3/ip_addresses/${ip}`, {
        headers: { 'x-apikey': VT_KEY }
      });
      const vtData = await vtRes.json();
      const stats = vtData?.data?.attributes?.last_analysis_stats || {};
      const malicious = stats.malicious || 0;
      const suspicious = stats.suspicious || 0;
      const total = Object.values(stats).reduce((a, b) => a + b, 0);
      vt = {
        verdict: malicious > 0 ? 'malicious' : suspicious > 0 ? 'suspicious' : 'clean',
        detections: malicious,
        total
      };
    } catch(e) { vt.verdict = 'error'; }

    // AbuseIPDB
    let abuse = { verdict: 'unknown', score: 0 };
    try {
      const abuseRes = await fetch(`https://api.abuseipdb.com/api/v2/check?ipAddress=${ip}&maxAgeInDays=90`, {
        headers: { 'Key': ABUSE_KEY, 'Accept': 'application/json' }
      });
      const abuseData = await abuseRes.json();
      const score = abuseData?.data?.abuseConfidenceScore ?? 0;
      abuse = {
        verdict: score > 50 ? 'malicious' : score > 10 ? 'suspicious' : 'clean',
        score
      };
    } catch(e) { abuse.verdict = 'error'; }

    // Extract SSL from banner data
    let ssl = null;
    if (Array.isArray(shodan.data)) {
      for (const item of shodan.data) {
        if (item.ssl?.cert) {
          ssl = {
            subject: item.ssl.cert.subject?.CN || null,
            issuer:  item.ssl.cert.issuer?.O  || null,
            expires: item.ssl.cert.expires    || null,
          };
          break;
        }
      }
    }

    return res.status(200).json({
      shodan: {
        ip_str:       shodan.ip_str,
        hostnames:    shodan.hostnames || [],
        org:          shodan.org,
        isp:          shodan.isp,
        asn:          shodan.asn,
        country_name: shodan.country_name,
        city:         shodan.city,
        os:           shodan.os,
        ports:        shodan.ports || [],
        vulns:        Object.keys(shodan.vulns || {}),
        last_update:  shodan.last_update,
        ssl
      },
      vt,
      abuse
    });

  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
