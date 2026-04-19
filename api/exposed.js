const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://h3ad-sec.github.io';

const SVC_QUERIES = {
  rdp:     'port:3389 product:"Remote Desktop Protocol"',
  smb:     'port:445 product:"Samba"',
  telnet:  'port:23 product:"telnet"',
  jenkins: 'http.title:"Dashboard [Jenkins]"',
  kibana:  'http.title:"Kibana" port:5601',
  grafana: 'http.title:"Grafana" port:3000',
  mongo:   'port:27017 product:"MongoDB"',
  elastic: 'port:9200 product:"Elasticsearch"',
};

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Content-Type', 'application/json');

  const { service } = req.query;
  const query = SVC_QUERIES[service];
  if (!query) return res.status(400).json({ error: 'Unknown service' });

  try {
    const KEY = process.env.SHODAN_KEY;
    const url = `https://api.shodan.io/shodan/host/search?key=${KEY}&query=${encodeURIComponent(query)}&minify=false`;
    const r = await fetch(url);
    const data = await r.json();

    const hosts = (data.matches || []).map(h => ({
      ip_str: h.ip_str,
      port: h.port,
      org: h.org,
      country_name: h.location?.country_name,
      product: h.product,
    }));

    return res.status(200).json({ query, total: data.total, hosts });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
