const SVC_QUERIES = {
  rdp:     'port:3389 product:"Remote Desktop Protocol"',
  smb:     'port:445 product:"Samba"',
  telnet:  'port:23 product:"telnet"',
  jenkins: 'http.title:"Dashboard [Jenkins]"',
  kibana:  'http.title:"Kibana" port:5601',
  grafana: 'http.title:"Grafana"',
  mongo:   'port:27017 product:"MongoDB"',
  elastic: 'port:9200 product:"Elasticsearch"',
};

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const allowed = process.env.ALLOWED_ORIGIN || '';
  res.setHeader('Access-Control-Allow-Origin', allowed.includes(origin) ? origin : allowed.split(',')[0].trim());
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { service } = req.query;
  const query = SVC_QUERIES[service];
  if (!query) return res.status(400).json({ error: 'Unknown service' });

  try {
    const KEY = process.env.SHODAN_KEY;
    const r = await fetch(`https://api.shodan.io/shodan/host/search?key=${KEY}&query=${encodeURIComponent(query)}&minify=false`);
    if (!r.ok) return res.status(500).json({ error: `Shodan error: ${r.status}` });
    const data = await r.json();

    const hosts = (data.matches || []).map(h => ({
      ip_str:       h.ip_str,
      port:         h.port,
      org:          h.org,
      country_name: h.location?.country_name,
      product:      h.product,
    }));

    return res.status(200).json({ query, total: data.total, hosts });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
