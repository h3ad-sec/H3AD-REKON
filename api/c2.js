const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://h3ad-sec.github.io';

const C2_QUERIES = {
  cobaltstrike: 'product:"Cobalt Strike Beacon"',
  metasploit:   'product:"Metasploit" http.title:"Metasploit"',
  sliver:       'ssl.cert.subject.cn:sliver http.title:"Sliver"',
  havoc:        'http.html:"Havoc C2" port:443',
  brute_ratel:  'product:"Brute Ratel C4"',
};

export default async function handler(req, res) {
  if (req.method === 'OPTIONS') return res.status(200).end();
  res.setHeader('Access-Control-Allow-Origin', ALLOWED_ORIGIN);
  res.setHeader('Content-Type', 'application/json');

  const { framework } = req.query;
  const query = C2_QUERIES[framework];
  if (!query) return res.status(400).json({ error: 'Unknown framework' });

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
      data: h.data,
    }));

    return res.status(200).json({ query, total: data.total, hosts });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
