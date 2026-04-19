const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://h3ad-sec.github.io';

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Content-Type', 'application/json');

  const { id } = req.query;
  if (!id) return res.status(400).json({ error: 'CVE id parameter required' });

  try {
    const KEY = process.env.SHODAN_KEY;
    const query = `vuln:${id}`;
    const url = `https://api.shodan.io/shodan/host/search?key=${KEY}&query=${encodeURIComponent(query)}&minify=false`;
    const r = await fetch(url);
    const data = await r.json();

    const hosts = (data.matches || []).map(h => ({
      ip_str: h.ip_str,
      port: h.port,
      org: h.org,
      country_name: h.location?.country_name,
      product: h.product,
      version: h.version,
    }));

    return res.status(200).json({ query, total: data.total, hosts });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
