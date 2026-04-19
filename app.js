
const API_BASE = 'https://h3ad-rekon.vercel.app';

const RISKY_PORTS = [21,22,23,25,3389,445,139,1433,3306,5432,6379,27017,9200,5601,8080,8443];
const RISKY_LABELS = {21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',3389:'RDP',445:'SMB',139:'NetBIOS',1433:'MSSQL',3306:'MySQL',5432:'PostgreSQL',6379:'Redis',27017:'MongoDB',9200:'Elasticsearch',5601:'Kibana',8080:'HTTP-Alt',8443:'HTTPS-Alt'};

function showSection(name) {
  document.querySelectorAll('.tool-section').forEach(s => s.classList.remove('active-section'));
  document.getElementById(name).classList.add('active-section');
  document.querySelectorAll('.module-grid .module-card').forEach(c => c.classList.remove('active-card'));
  const target = [...document.querySelectorAll('.module-grid .module-card')].find(c => c.getAttribute('href') === '#' + name);
  if (target) target.classList.add('active-card');
}

function showLoading(id) {
  const el = document.getElementById(id);
  el.style.display = 'block';
  el.innerHTML = '<div class="loading">[ SCANNING... PLEASE WAIT ]</div>';
}
function showError(id, msg) {
  const el = document.getElementById(id);
  el.style.display = 'block';
  el.innerHTML = `<div class="error-msg">[ ERROR ] ${msg}</div>`;
}
function portBadge(port) {
  const risky = RISKY_PORTS.includes(port);
  const label = RISKY_LABELS[port] ? ` (${RISKY_LABELS[port]})` : '';
  return `<span class="port-badge ${risky ? 'risky' : 'common'}">${port}${label}</span>`;
}
function verdictClass(v) {
  if (!v) return 'unknown';
  v = v.toLowerCase();
  if (v.includes('malicious') || v.includes('bad') || v.includes('abuse')) return 'malicious';
  if (v.includes('clean') || v.includes('safe') || v.includes('none')) return 'clean';
  if (v.includes('suspicious')) return 'suspicious';
  return 'unknown';
}
function row(key, val) {
  return `<div class="result-row"><span class="result-key">${key}</span><span class="result-val">${val}</span></div>`;
}
function section(label, content) {
  return `<div class="result-section"><div class="result-label">${label}</div>${content}</div>`;
}

async function lookupIP() {
  const ip = document.getElementById('ip-input').value.trim();
  if (!ip) return;
  showLoading('ip-result');
  try {
    const res = await fetch(`${API_BASE}/api/host?ip=${encodeURIComponent(ip)}`);
    const data = await res.json();
    if (data.error) return showError('ip-result', data.error);
    renderIPResult(data, ip);
  } catch(e) { showError('ip-result', 'Request failed. Check API connection.'); }
}
function renderIPResult(d, ip) {
  const sh = d.shodan || {};
  const ports = (sh.ports || []).map(portBadge).join('');
  const cves = (sh.vulns || []).map(c => `<span class="port-badge risky">${c}</span>`).join('') || 'None detected';
  const verdicts = `
    <div class="verdict-row">
      <div class="verdict-card"><div class="verdict-source">SHODAN</div><div class="verdict-badge ${sh.ports?.some(p=>RISKY_PORTS.includes(p))?'suspicious':'clean'}">${sh.ports?.some(p=>RISKY_PORTS.includes(p)) ? 'RISKY PORTS OPEN' : 'NO RISKY PORTS'}</div></div>
      <div class="verdict-card"><div class="verdict-source">VIRUSTOTAL</div><div class="verdict-badge ${verdictClass(d.vt?.verdict)}">${(d.vt?.verdict || 'unknown').toUpperCase()}</div></div>
      <div class="verdict-card"><div class="verdict-source">ABUSEIPDB</div><div class="verdict-badge ${verdictClass(d.abuse?.verdict)}">${(d.abuse?.verdict || 'unknown').toUpperCase()}</div></div>
    </div>`;
  document.getElementById('ip-result').innerHTML = `
    ${section('VERDICT', verdicts)}
    ${section('HOST INFO', `${row('IP', sh.ip_str || ip)}${row('Hostnames', (sh.hostnames||[]).join(', ') || 'None')}${row('Organization', sh.org || 'Unknown')}${row('ISP', sh.isp || 'Unknown')}${row('ASN', sh.asn || 'Unknown')}${row('Country', (sh.country_name || '') + (sh.city ? ', ' + sh.city : ''))}${row('OS', sh.os || 'Unknown')}${row('Last Updated', sh.last_update || 'Unknown')}`)}
    ${section('OPEN PORTS', `<div class="port-badges">${ports || 'None'}</div>`)}
    ${section('VULNERABILITIES', `<div class="port-badges">${cves}</div>`)}
  `;
}

async function footprintOrg() {
  const org = document.getElementById('org-input').value.trim();
  if (!org) return;
  showLoading('org-result');
  try {
    const res = await fetch(`${API_BASE}/api/footprint?org=${encodeURIComponent(org)}`);
    const data = await res.json();
    if (data.error) return showError('org-result', data.error);
    const rows = (data.hosts || []).slice(0, 30).map(h => `<tr><td>${h.ip_str}</td><td>${(h.ports||[]).slice(0,5).join(', ')}</td><td>${h.org || 'N/A'}</td><td>${h.country_name || 'N/A'}</td><td>${(h.vulns||[]).length}</td></tr>`).join('');
    document.getElementById('org-result').innerHTML = `${section('FOOTPRINT SUMMARY', `${row('Query', data.query || 'N/A')}${row('Total Results', data.total || 0)}`)}${section('EXPOSED ASSETS', `<table class="host-table"><thead><tr><th>IP</th><th>PORTS</th><th>ORG</th><th>COUNTRY</th><th>VULNS</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No results</td></tr>'}</tbody></table>`)}`;
  } catch(e) { showError('org-result', 'Request failed.'); }
}

async function searchCVE() {
  const cve = document.getElementById('cve-input').value.trim();
  if (!cve) return;
  showLoading('cve-result');
  try {
    const res = await fetch(`${API_BASE}/api/cve?id=${encodeURIComponent(cve)}`);
    const data = await res.json();
    if (data.error) return showError('cve-result', data.error);
    const rows = (data.hosts || []).slice(0, 20).map(h => `<tr><td>${h.ip_str}</td><td>${h.port || 'N/A'}</td><td>${h.org || 'N/A'}</td><td>${h.country_name || 'N/A'}</td><td>${h.product || 'N/A'} ${h.version || ''}</td></tr>`).join('');
    document.getElementById('cve-result').innerHTML = `${section('CVE EXPOSURE', `${row('CVE ID', cve)}${row('Exposed Hosts', data.total || 0)}`)}${section('AFFECTED HOSTS', `<table class="host-table"><thead><tr><th>IP</th><th>PORT</th><th>ORG</th><th>COUNTRY</th><th>PRODUCT</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No results</td></tr>'}</tbody></table>`)}`;
  } catch(e) { showError('cve-result', 'Request failed.'); }
}

async function detectC2() {
  const framework = document.getElementById('c2-select').value;
  showLoading('c2-result');
  try {
    const res = await fetch(`${API_BASE}/api/c2?framework=${framework}`);
    const data = await res.json();
    if (data.error) return showError('c2-result', data.error);
    const rows = (data.hosts || []).slice(0, 20).map(h => `<tr><td>${h.ip_str}</td><td>${h.port || 'N/A'}</td><td>${h.org || 'N/A'}</td><td>${h.country_name || 'N/A'}</td><td>${h.data ? h.data.substring(0,60)+'...' : 'N/A'}</td></tr>`).join('');
    document.getElementById('c2-result').innerHTML = `${section('C2 HUNT RESULTS', `${row('Framework', framework.toUpperCase())}${row('Exposed Servers', data.total || 0)}${row('Shodan Query', data.query || 'N/A')}`)}${section('DETECTED C2 SERVERS', `<table class="host-table"><thead><tr><th>IP</th><th>PORT</th><th>ORG</th><th>COUNTRY</th><th>BANNER</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No results</td></tr>'}</tbody></table>`)}`;
  } catch(e) { showError('c2-result', 'Request failed.'); }
}

async function findExposed() {
  const svc = document.getElementById('svc-select').value;
  showLoading('svc-result');
  try {
    const res = await fetch(`${API_BASE}/api/exposed?service=${svc}`);
    const data = await res.json();
    if (data.error) return showError('svc-result', data.error);
    const rows = (data.hosts || []).slice(0, 20).map(h => `<tr><td>${h.ip_str}</td><td>${h.port || 'N/A'}</td><td>${h.org || 'N/A'}</td><td>${h.country_name || 'N/A'}</td><td>${h.product || 'N/A'}</td></tr>`).join('');
    document.getElementById('svc-result').innerHTML = `${section('EXPOSED SERVICE RESULTS', `${row('Service', svc.toUpperCase())}${row('Exposed Globally', data.total || 0)}${row('Shodan Query', data.query || 'N/A')}`)}${section('EXPOSED HOSTS', `<table class="host-table"><thead><tr><th>IP</th><th>PORT</th><th>ORG</th><th>COUNTRY</th><th>PRODUCT</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No results</td></tr>'}</tbody></table>`)}`;
  } catch(e) { showError('svc-result', 'Request failed.'); }
}

function toggleDrawer() { document.getElementById('navDrawer').classList.toggle('open'); }
function closeDrawer() { document.getElementById('navDrawer').classList.remove('open'); }
document.addEventListener('click', e => {
  const drawer = document.getElementById('navDrawer');
  const ham = document.getElementById('hamburger');
  if (drawer.classList.contains('open') && !drawer.contains(e.target) && !ham.contains(e.target)) closeDrawer();
});

function setLogo(theme) {
  const el = document.getElementById('logoImg');
  if (el) el.src = theme === 'light' ? 'https://h3ad-sec.github.io/logo-light.png' : 'https://h3ad-sec.github.io/logo-dark.png';
}
function toggleTheme() {
  document.body.classList.toggle('light');
  document.body.classList.toggle('dark');
  const t = document.body.classList.contains('light') ? 'light' : 'dark';
  localStorage.setItem('theme', t);
  setLogo(t);
}
const saved = localStorage.getItem('theme');
if (saved === 'light') {
  document.body.classList.add('light');
  setLogo('light');
} else {
  document.body.classList.add('dark');
  setLogo('dark');
}

const canvas = document.getElementById('matrix');
const ctx = canvas.getContext('2d');
const chars = ['10.0.','172.16.','192.168.','127.0.0.1','443','80','8080','3389','445','22','53','HTTP','HTTPS','TLS1.3','SMBv2','DNS','LDAP','Kerberos','RDP','T1003','T1059','T1047','T1021','IOC','YARA','SIGMA','STIX2','SHA256','LSASS','NTDS.dit','Shellcode','Loader','C2','Beacon','Pivot','Persistence','Exfil','powershell','cmd.exe','wmic','mimikatz','Sysmon','EDR','XDR','SIEM','4624','4688','SHODAN','REKON','ALERT','DETECT','HUNT','RCE','APT','ThreatActor'];
let drops = [];
function initMatrix() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;
  drops = Array(Math.floor(window.innerWidth / 18)).fill(1);
}
function drawMatrix() {
  const light = document.body.classList.contains('light');
  ctx.fillStyle = light ? 'rgba(245,247,251,0.08)' : 'rgba(0,0,0,0.12)';
  ctx.fillRect(0, 0, canvas.width, canvas.height);
  ctx.fillStyle = light ? '#0077ff' : '#00ff9f';
  ctx.font = '13px monospace';
  for (let i = 0; i < drops.length; i++) {
    ctx.fillText(chars[Math.floor(Math.random() * chars.length)], i * 18, drops[i] * 18);
    if (drops[i] * 18 > canvas.height && Math.random() > 0.975) drops[i] = 0;
    drops[i]++;
  }
  requestAnimationFrame(drawMatrix);
}
window.addEventListener('resize', initMatrix);
initMatrix();
drawMatrix();

document.getElementById('ip-input').addEventListener('keydown', e => { if (e.key === 'Enter') lookupIP(); });
document.getElementById('org-input').addEventListener('keydown', e => { if (e.key === 'Enter') footprintOrg(); });
document.getElementById('cve-input').addEventListener('keydown', e => { if (e.key === 'Enter') searchCVE(); });
