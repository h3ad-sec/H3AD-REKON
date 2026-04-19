export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowed = process.env.ALLOWED_ORIGIN || '';
  res.setHeader('Access-Control-Allow-Origin', allowed.includes(origin) ? origin : allowed.split(',')[0].trim());
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { id } = req.query;
  if (!id) return res.status(400).json({ error: 'CVE id required' });

  try {
    const KEY = process.env.SHODAN_KEY;
    const query = `vuln:${id}`;
    const r = await fetch(`https://api.shodan.io/shodan/host/search?key=${KEY}&query=${encodeURIComponent(query)}&minify=false`);
    if (!r.ok) return res.status(500).json({ error: `Shodan error: ${r.status}` });
    const data = await r.json();

    const hosts = (data.matches || []).map(h => ({
      ip_str:       h.ip_str,
      port:         h.port,
      org:          h.org,
      country_name: h.location?.country_name,
      product:      h.product,
      version:      h.version,
    }));

    return res.status(200).json({ query, total: data.total, hosts });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
