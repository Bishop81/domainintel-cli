/**
 * DomainIntel CLI
 *
 * A terminal interface to the same domain-intelligence analyzers that power
 * domainintel.app and the DomainIntel MCP server: WHOIS, DNS, SSL/TLS, HTTP
 * security headers, reputation (DNSBL/Spamhaus) and subdomain discovery.
 *
 * Everything runs locally from your machine. Domain queries are sent straight
 * to the authoritative DNS / WHOIS / TLS endpoints and crt.sh, never to a
 * domainintel.app server.
 *
 * Run from source with `node cli/index.mjs <domain>` (or `npm run cli`), or
 * build the standalone bundle with `npm run build:cli` and run `npx
 * @domainintel/cli`.
 */

// Static default imports (not createRequire) so esbuild can follow the graph
// and bundle the analyzers into a single self-contained file. Node's ESM loader
// exposes a CommonJS module's module.exports as the default import, so this also
// works when run directly with `node cli/index.mjs`.
import validatorPkg from './lib/utils/validator.js';
import analyzersPkg from './lib/analyzers/index.js';
import whoisPkg from './lib/analyzers/whois.js';
import dnsPkg from './lib/analyzers/dns.js';
import sslPkg from './lib/analyzers/ssl.js';
import headersPkg from './lib/analyzers/headers.js';
import reputationPkg from './lib/analyzers/reputation.js';
import subdomainPkg from './lib/analyzers/subdomain.js';

const { validateDomain } = validatorPkg;
const { normalizeDomain, analyzeDomain } = analyzersPkg;
const { analyzeWhois } = whoisPkg;
const { analyzeDns, checkCaaRecords, checkDnsMisconfigurations } = dnsPkg;
const { analyzeSsl } = sslPkg;
const { analyzeHeaders } = headersPkg;
const { analyzeReputation } = reputationPkg;
const { analyzeSubdomains } = subdomainPkg;

const VERSION = '1.0.0';

// Exit codes: 0 = clean, 1 = ran but found problems (only with --exit-code),
// 2 = could not run (bad usage, invalid domain, analysis failure).
const EXIT_OK = 0;
const EXIT_ISSUES = 1;
const EXIT_ERROR = 2;

const COMMANDS = ['full', 'dns', 'whois', 'ssl', 'headers', 'reputation', 'subdomains'];
const COMMAND_ALIASES = {
  reputation: 'reputation',
  rep: 'reputation',
  subdomains: 'subdomains',
  subs: 'subdomains',
  subdomain: 'subdomains',
  header: 'headers',
  headers: 'headers',
  cert: 'ssl',
  tls: 'ssl',
  ssl: 'ssl',
  dns: 'dns',
  whois: 'whois',
  report: 'full',
  full: 'full'
};

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const opts = {
    command: null,
    domain: null,
    json: false,
    color: undefined, // resolved later against TTY / NO_COLOR
    exitCode: false,
    debug: false,
    failUnder: null,
    help: false,
    version: false,
    _positionals: []
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    switch (arg) {
      case '--json':
        opts.json = true;
        break;
      case '--no-color':
        opts.color = false;
        break;
      case '--color':
        opts.color = true;
        break;
      case '-e':
      case '--exit-code':
        opts.exitCode = true;
        break;
      case '--debug':
        opts.debug = true;
        break;
      case '--fail-under':
        opts.failUnder = Number(argv[++i]);
        break;
      case '-h':
      case '--help':
        opts.help = true;
        break;
      case '-v':
      case '--version':
        opts.version = true;
        break;
      default:
        if (arg.startsWith('--fail-under=')) {
          opts.failUnder = Number(arg.slice('--fail-under='.length));
        } else if (arg.startsWith('-') && arg !== '-') {
          opts._unknown = arg;
        } else {
          opts._positionals.push(arg);
        }
    }
  }

  // Resolve command + domain from positionals. The first positional is either a
  // known command (then the next is the domain) or the domain itself (default
  // command = full report).
  const [first, second] = opts._positionals;
  if (first && COMMAND_ALIASES[first.toLowerCase()]) {
    opts.command = COMMAND_ALIASES[first.toLowerCase()];
    opts.domain = second || null;
  } else {
    opts.command = 'full';
    opts.domain = first || null;
  }

  return opts;
}

// ---------------------------------------------------------------------------
// Colour + formatting helpers (zero dependencies)
// ---------------------------------------------------------------------------

let useColor = true;

const ANSI = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  gray: '\x1b[90m'
};

function paint(code, s) {
  if (!useColor) return s;
  return code + s + ANSI.reset;
}

const c = {
  bold: (s) => paint(ANSI.bold, s),
  dim: (s) => paint(ANSI.dim, s),
  red: (s) => paint(ANSI.red, s),
  green: (s) => paint(ANSI.green, s),
  yellow: (s) => paint(ANSI.yellow, s),
  blue: (s) => paint(ANSI.blue, s),
  magenta: (s) => paint(ANSI.magenta, s),
  cyan: (s) => paint(ANSI.cyan, s),
  gray: (s) => paint(ANSI.gray, s)
};

function out(s = '') {
  process.stdout.write(s + '\n');
}

function err(s = '') {
  process.stderr.write(s + '\n');
}

// Visible length, ignoring ANSI escapes, for column alignment.
function visibleLength(s) {
  return s.replace(/\x1b\[[0-9;]*m/g, '').length;
}

function padEndVisible(s, width) {
  const pad = width - visibleLength(s);
  return pad > 0 ? s + ' '.repeat(pad) : s;
}

function severityColor(severity) {
  if (severity === 'high') return c.red;
  if (severity === 'medium') return c.yellow;
  return c.gray;
}

function ratingColor(rating) {
  if (!rating) return c.gray;
  if (rating === 'A+' || rating === 'A') return c.green;
  if (rating === 'B' || rating === 'C') return c.yellow;
  return c.red;
}

const CHECK = () => c.green('✓');
const CROSS = () => c.red('✗');
const DOT = () => c.gray('•');

function yesNo(value, { goodWhenTrue = true } = {}) {
  if (value) return goodWhenTrue ? c.green('yes') : c.red('yes');
  return goodWhenTrue ? c.red('no') : c.green('no');
}

function sectionTitle(title) {
  out();
  out(c.bold(c.cyan(title)));
  out(c.gray('─'.repeat(Math.max(title.length, 12))));
}

// Render aligned "label  value" rows.
function kvRows(rows) {
  const labelWidth = rows.reduce((m, [k]) => Math.max(m, k.length), 0);
  for (const [k, v] of rows) {
    if (v === undefined || v === null) continue;
    out(`  ${c.gray(padEndVisible(k, labelWidth))}  ${v}`);
  }
}

// ---------------------------------------------------------------------------
// Spinner (stderr only, TTY only)
// ---------------------------------------------------------------------------

const SPINNER_FRAMES = ['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];

function startSpinner(label) {
  if (!process.stderr.isTTY) return () => {};
  let i = 0;
  process.stderr.write('\x1b[?25l'); // hide cursor
  const timer = setInterval(() => {
    const frame = useColor ? c.cyan(SPINNER_FRAMES[i]) : SPINNER_FRAMES[i];
    process.stderr.write(`\r${frame} ${label}`);
    i = (i + 1) % SPINNER_FRAMES.length;
  }, 80);
  return () => {
    clearInterval(timer);
    process.stderr.write('\r\x1b[K'); // clear line
    process.stderr.write('\x1b[?25h'); // show cursor
  };
}

// ---------------------------------------------------------------------------
// Misc helpers
// ---------------------------------------------------------------------------

function daysUntil(dateStr) {
  if (!dateStr) return null;
  const date = new Date(dateStr);
  if (isNaN(date.getTime())) return null;
  return Math.ceil((date - new Date()) / (1000 * 60 * 60 * 24));
}

function expiryStyledDays(days) {
  if (days === null || days === undefined) return null;
  if (days < 0) return c.red(`expired ${Math.abs(days)} days ago`);
  if (days < 14) return c.red(`${days} days`);
  if (days < 30) return c.yellow(`${days} days`);
  return c.green(`${days} days`);
}

function ratingBadge(score) {
  if (!score) return '';
  const label = ` ${score.rating} `;
  const colored = ratingColor(score.rating)(c.bold(label));
  return `${colored} ${c.gray(`${score.overall}/100`)}`;
}

// Each renderer returns an array of issue strings (problems found). With
// --exit-code, a non-empty list means exit 1.

// ---------------------------------------------------------------------------
// DNS
// ---------------------------------------------------------------------------

async function gatherDns(domain) {
  const dns = await analyzeDns(domain);
  const [caa, warnings] = await Promise.all([
    checkCaaRecords(domain).catch(() => ({ hasCaa: false, records: [] })),
    Promise.resolve(checkDnsMisconfigurations(dns))
  ]);
  return { ...dns, caa, warnings: warnings.warnings || [] };
}

// Node's dns.resolveCaa returns objects like { critical: 0, issue: 'letsencrypt.org' }.
function formatCaa(r) {
  const key = Object.keys(r).find((k) => k !== 'critical');
  return key ? `${key} "${r[key]}"` : JSON.stringify(r);
}

const MAX_RECORD_ROWS = 12;

function renderDns(domain, dns) {
  const issues = [];
  sectionTitle('DNS records');

  const recordGroups = [
    ['A', dns.a],
    ['AAAA', dns.aaaa],
    ['MX', (dns.mx || []).map((m) => `${m.exchange || c.gray('(null MX - accepts no mail)')} ${c.gray(`(priority ${m.priority})`)}`)],
    ['NS', dns.ns],
    ['CNAME', dns.cname],
    ['TXT', dns.txt],
    ['CAA', (dns.caa?.records || []).map(formatCaa)]
  ];

  let any = false;
  const typeWidth = 5;
  for (const [type, values] of recordGroups) {
    if (!values || values.length === 0) continue;
    any = true;
    const shown = values.slice(0, MAX_RECORD_ROWS);
    shown.forEach((v, idx) => {
      const label = idx === 0 ? c.magenta(padEndVisible(type, typeWidth)) : ' '.repeat(typeWidth);
      out(`  ${label}  ${v}`);
    });
    if (values.length > MAX_RECORD_ROWS) {
      out(`  ${' '.repeat(typeWidth)}  ${c.gray(`+${values.length - MAX_RECORD_ROWS} more (use --json for all)`)}`);
    }
  }
  if (!any) out(c.gray('  No records resolved.'));

  out();
  kvRows([
    ['SPF', dns.hasSpf ? CHECK() + ' present' : CROSS() + ' missing'],
    ['DMARC', dns.hasDmarc ? CHECK() + ' present' : CROSS() + ' missing'],
    ['CAA', dns.caa?.hasCaa ? CHECK() + ' present' : c.gray('not set')]
  ]);

  if (dns.warnings && dns.warnings.length) {
    out();
    out(c.bold('  Warnings'));
    for (const w of dns.warnings) {
      const tag = severityColor(w.severity)(`[${w.severity}]`);
      out(`  ${tag} ${w.message}`);
      issues.push(`DNS ${w.type}: ${w.message}`);
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------
// WHOIS
// ---------------------------------------------------------------------------

function renderWhois(domain, whois) {
  const issues = [];
  sectionTitle('WHOIS');

  const expDays = daysUntil(whois.expirationDate);
  let expValue = whois.expirationDate || c.gray('unknown');
  if (expDays !== null) {
    expValue = `${whois.expirationDate} ${c.gray('(' )}${expiryStyledDays(expDays)}${c.gray(')')}`;
    if (expDays < 0) issues.push(`Domain registration expired ${Math.abs(expDays)} days ago`);
    else if (expDays < 30) issues.push(`Domain registration expires in ${expDays} days`);
  }

  kvRows([
    ['Registrar', whois.registrar || c.gray('unknown')],
    ['Created', whois.creationDate || c.gray('unknown')],
    ['Updated', whois.updatedDate || c.gray('unknown')],
    ['Expires', expValue],
    ['Privacy', whois.privacyEnabled ? c.green('enabled') : c.yellow('disabled')],
    ['Country', whois.registrantCountry || c.gray('unknown')]
  ]);
  return issues;
}

// ---------------------------------------------------------------------------
// SSL
// ---------------------------------------------------------------------------

function renderSsl(domain, ssl, failUnder) {
  const issues = [];
  sectionTitle('SSL / TLS certificate');

  if (!ssl || ssl.valid === false) {
    out(`  ${CROSS()} ${c.red(ssl?.error || 'No valid certificate')}`);
    issues.push(`SSL: ${ssl?.error || 'no valid certificate'}`);
    return issues;
  }

  const threshold = Number.isFinite(failUnder) ? failUnder : 0;
  const rows = [
    ['Issuer', ssl.issuer?.organization || ssl.issuer?.commonName || c.gray('unknown')],
    ['Subject', ssl.subject?.commonName || c.gray('unknown')],
    ['Valid from', (ssl.validFrom || '').split('T')[0] || c.gray('unknown')],
    ['Valid to', (ssl.validTo || '').split('T')[0] || c.gray('unknown')],
    ['Expires in', expiryStyledDays(ssl.daysRemaining)],
    ['Protocol', ssl.securityDetails?.protocol || c.gray('unknown')],
    ['Cipher', ssl.securityDetails?.cipher?.name || c.gray('unknown')]
  ];
  kvRows(rows);

  const sans = ssl.subjectAlternativeNames || [];
  if (sans.length) {
    out();
    out(`  ${c.gray('SANs')}  ${sans.slice(0, 8).join(', ')}${sans.length > 8 ? c.gray(` +${sans.length - 8} more`) : ''}`);
  }

  if (ssl.daysRemaining < 0) {
    issues.push('SSL certificate has expired');
  } else if (Number.isFinite(failUnder) && ssl.daysRemaining < threshold) {
    issues.push(`SSL certificate expires in ${ssl.daysRemaining} days (threshold ${threshold})`);
  }
  for (const w of ssl.warnings || []) {
    if (w.severity === 'high') issues.push(`SSL ${w.type}: ${w.message}`);
  }

  if (ssl.warnings && ssl.warnings.length) {
    out();
    out(c.bold('  Warnings'));
    for (const w of ssl.warnings) {
      out(`  ${severityColor(w.severity)(`[${w.severity}]`)} ${w.message}`);
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Headers
// ---------------------------------------------------------------------------

const CRITICAL_HEADERS = [
  'strict-transport-security',
  'content-security-policy',
  'x-frame-options',
  'x-content-type-options'
];

function renderHeaders(domain, headers) {
  const issues = [];
  sectionTitle('HTTP security headers');

  if (!headers || headers.success === false) {
    out(`  ${CROSS()} ${c.red(headers?.error || 'Could not retrieve headers')}`);
    issues.push(`Headers: ${headers?.error || 'could not retrieve'}`);
    return issues;
  }

  const sec = headers.securityAnalysis;
  out(`  ${c.bold('Grade')}  ${ratingColor(sec.securityScore.rating)(c.bold(sec.securityScore.rating))} ${c.gray(`(${sec.securityScore.percentage}%)`)}`);
  out();

  const entries = Object.entries(sec.securityHeaders);
  for (const [name, info] of entries) {
    const mark = info.present ? CHECK() : (CRITICAL_HEADERS.includes(name) ? CROSS() : DOT());
    out(`  ${mark} ${c.gray(name)}`);
  }

  for (const name of CRITICAL_HEADERS) {
    if (sec.securityHeaders[name] && !sec.securityHeaders[name].present) {
      issues.push(`Missing security header: ${name}`);
    }
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Reputation
// ---------------------------------------------------------------------------

function renderReputation(domain, rep) {
  const issues = [];
  sectionTitle('Reputation');

  if (rep.error) {
    out(`  ${CROSS()} ${c.red(rep.error)}`);
    return issues;
  }

  const scoreColor = rep.reputationScore >= 90 ? c.green : rep.reputationScore >= 60 ? c.yellow : c.red;
  out(`  ${c.bold('Score')}  ${scoreColor(c.bold(String(rep.reputationScore)))}${c.gray('/100')}`);
  out();

  const dnsblListed = rep.dnsbl?.listed;
  const spamhausListed = rep.spamhaus?.listed;
  kvRows([
    ['DNSBL', dnsblListed ? c.red('LISTED') : c.green('clean')],
    ['Spamhaus', spamhausListed ? c.red('LISTED') : c.green('clean')],
    ['Safe Browsing', rep.safeBrowsing?.safe === false ? c.red('flagged') : c.green('clean')]
  ]);

  if (dnsblListed) {
    const lists = (rep.dnsbl.detections || []).filter((d) => d.listed).map((d) => d.list);
    out();
    out(`  ${c.red('Listed on:')} ${lists.join(', ')}`);
    issues.push(`Listed on DNSBL: ${lists.join(', ')}`);
  }
  if (spamhausListed) issues.push('IP listed in Spamhaus ZEN');
  return issues;
}

// ---------------------------------------------------------------------------
// Subdomains
// ---------------------------------------------------------------------------

function renderSubdomains(domain, subs) {
  sectionTitle('Subdomains');

  if (subs.success === false) {
    out(`  ${CROSS()} ${c.red(subs.error || 'Subdomain discovery failed')}`);
    return [];
  }

  out(`  ${c.gray('Found')} ${c.bold(String(subs.totalFound))} ${c.gray('in CT logs,')} ${c.bold(String(subs.activeCount))} ${c.gray('active')}`);
  if (subs.activeCount) out();

  const active = subs.subdomains || [];
  const nameWidth = active.reduce((m, s) => Math.max(m, s.subdomain.length), 0);
  for (const s of active.slice(0, 40)) {
    let target = '';
    if (s.cname) target = c.gray(`CNAME → ${s.cname}`);
    else if (s.ipv4.length) target = c.gray(s.ipv4.join(', '));
    else if (s.ipv6.length) target = c.gray(s.ipv6.join(', '));
    out(`  ${DOT()} ${padEndVisible(s.subdomain, nameWidth)}  ${target}`);
  }
  if (active.length > 40) out(c.gray(`  ... and ${active.length - 40} more`));
  return [];
}

// ---------------------------------------------------------------------------
// Full report
// ---------------------------------------------------------------------------

function renderFull(domain, report) {
  const issues = [];

  out();
  out(`${c.bold('Security score')}  ${ratingBadge(report.securityScore)}`);

  if (report.whois && !report.whois.error) issues.push(...renderWhois(domain, report.whois));
  if (report.dns && !report.dns.error) issues.push(...renderDns(domain, report.dns));
  if (report.ssl) issues.push(...renderSsl(domain, report.ssl, null));
  if (report.headers) issues.push(...renderHeaders(domain, report.headers));
  if (report.reputation) issues.push(...renderReputation(domain, report.reputation));
  if (report.subdomains) renderSubdomains(domain, report.subdomains);

  if (report.securityScore && ['D', 'F'].includes(report.securityScore.rating)) {
    issues.unshift(`Overall security grade is ${report.securityScore.rating}`);
  }
  return issues;
}

// ---------------------------------------------------------------------------
// Command dispatch
// ---------------------------------------------------------------------------

async function runCommand(opts) {
  const { command, domain } = opts;

  const spinnerLabel = `Analyzing ${c.bold(domain)} ${c.gray(`(${command})`)}`;
  const stop = opts.json ? () => {} : startSpinner(spinnerLabel);

  let data;
  let issues = [];
  try {
    switch (command) {
      case 'dns':
        data = await gatherDns(domain);
        break;
      case 'whois':
        data = await analyzeWhois(domain);
        break;
      case 'ssl':
        data = await analyzeSsl(domain);
        break;
      case 'headers':
        data = await analyzeHeaders(domain);
        break;
      case 'reputation':
        data = await analyzeReputation(domain);
        break;
      case 'subdomains':
        data = await analyzeSubdomains(domain);
        break;
      case 'full':
      default:
        data = await analyzeDomain(domain);
        break;
    }
  } finally {
    stop();
  }

  if (opts.json) {
    out(JSON.stringify(command === 'full' ? data : { domain, ...wrap(command, data) }, null, 2));
    // JSON mode still honours --exit-code by recomputing issues silently.
    issues = collectIssues(command, domain, data, opts);
    return issues;
  }

  out(`${c.bold(c.blue('domainintel'))} ${c.gray('•')} ${c.bold(domain)}`);

  switch (command) {
    case 'dns':
      issues = renderDns(domain, data);
      break;
    case 'whois':
      issues = renderWhois(domain, data);
      break;
    case 'ssl':
      issues = renderSsl(domain, data, opts.failUnder);
      break;
    case 'headers':
      issues = renderHeaders(domain, data);
      break;
    case 'reputation':
      issues = renderReputation(domain, data);
      break;
    case 'subdomains':
      issues = renderSubdomains(domain, data);
      break;
    case 'full':
    default:
      issues = renderFull(domain, data);
      break;
  }

  out();
  if (issues.length === 0) {
    out(`${CHECK()} ${c.green('No issues detected.')}`);
  } else {
    out(`${c.yellow(`⚠ ${issues.length} issue${issues.length === 1 ? '' : 's'} found:`)}`);
    for (const issue of issues) out(`  ${c.gray('•')} ${issue}`);
  }
  out(c.gray(`\nFull report: https://domainintel.app/?domain=${encodeURIComponent(domain)}`));
  return issues;
}

// Mirror the JSON shape the MCP server returns for single-analyzer calls.
function wrap(command, data) {
  switch (command) {
    case 'dns':
      return { dns: data };
    case 'whois':
      return { whois: data };
    case 'ssl':
      return { ssl: data };
    case 'headers':
      return { headers: data };
    case 'reputation':
      return { reputation: data };
    case 'subdomains':
      return { subdomains: data };
    default:
      return data;
  }
}

// Compute issues without rendering (used by --json + --exit-code).
function collectIssues(command, domain, data, opts) {
  const sink = [];
  const capture = (fn) => {
    const realOut = process.stdout.write.bind(process.stdout);
    process.stdout.write = () => true;
    try {
      return fn();
    } finally {
      process.stdout.write = realOut;
    }
  };
  // Reuse the renderers purely for their issue logic; suppress their output.
  switch (command) {
    case 'dns':
      return capture(() => renderDns(domain, data));
    case 'whois':
      return capture(() => renderWhois(domain, data));
    case 'ssl':
      return capture(() => renderSsl(domain, data, opts.failUnder));
    case 'headers':
      return capture(() => renderHeaders(domain, data));
    case 'reputation':
      return capture(() => renderReputation(domain, data));
    case 'subdomains':
      return [];
    default:
      return capture(() => renderFull(domain, data));
  }
}

// ---------------------------------------------------------------------------
// Help / version
// ---------------------------------------------------------------------------

function printVersion() {
  out(`domainintel ${VERSION}`);
}

function printHelp() {
  const b = (s) => c.bold(s);
  out(`${b('domainintel')} ${c.gray(`v${VERSION}`)} - domain intelligence from your terminal

${b('USAGE')}
  domainintel <domain>                 Full report (default)
  domainintel <command> <domain>       Run a single check

${b('COMMANDS')}
  full         WHOIS + DNS + SSL + headers + reputation + subdomains
  dns          A/AAAA/MX/TXT/NS/CNAME/CAA + SPF/DMARC + misconfig warnings
  whois        Registrar, dates, privacy status, registrant country
  ssl          TLS certificate: validity, issuer, expiry, protocol
  headers      HTTP security headers with a letter grade
  reputation   DNSBL / Spamhaus blocklist checks
  subdomains   Discover subdomains via Certificate Transparency logs

${b('OPTIONS')}
  --json               Output raw JSON (pipeable to jq)
  -e, --exit-code      Exit 1 if the check finds problems (for CI gates)
  --fail-under <days>  (ssl) exit 1 if the certificate expires within <days>
  --no-color           Disable coloured output
  --debug              Show analyzer debug logs on stderr
  -h, --help           Show this help
  -v, --version        Show version

${b('EXAMPLES')}
  domainintel example.com
  domainintel dns example.com --json | jq '.dns.mx'
  domainintel ssl example.com --fail-under 14 --exit-code
  cat domains.txt | xargs -I{} domainintel whois {} --json

Everything runs locally. Queries go straight to DNS / WHOIS / TLS / crt.sh,
never to a domainintel.app server.
Docs: https://domainintel.app/guides/domain-intelligence-mcp-server`);
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const opts = parseArgs(process.argv.slice(2));

  // Resolve colour: explicit flag wins, else enable only on a TTY without
  // NO_COLOR set.
  if (opts.color === undefined) {
    useColor = process.stdout.isTTY && !process.env.NO_COLOR;
  } else {
    useColor = opts.color;
  }

  if (opts.version) {
    printVersion();
    process.exit(EXIT_OK);
  }
  if (opts.help) {
    printHelp();
    process.exit(EXIT_OK);
  }
  if (opts._unknown) {
    err(c.red(`Unknown option: ${opts._unknown}`));
    err(c.gray('Run `domainintel --help` for usage.'));
    process.exit(EXIT_ERROR);
  }

  if (!opts.domain) {
    printHelp();
    process.exit(EXIT_ERROR);
  }

  if (opts.command !== 'full' && !COMMANDS.includes(opts.command)) {
    err(c.red(`Unknown command: ${opts.command}`));
    process.exit(EXIT_ERROR);
  }

  const normalized = normalizeDomain(String(opts.domain));
  if (!validateDomain(normalized)) {
    err(`${c.red('Invalid domain:')} "${opts.domain}"`);
    err(c.gray('Provide a bare hostname like "example.com".'));
    process.exit(EXIT_ERROR);
  }
  opts.domain = normalized;

  // The analyzers emit verbose console.log/console.error debug output. Silence
  // it so stdout stays clean (critical for --json) unless --debug is set.
  if (!opts.debug) {
    console.log = () => {};
    console.error = () => {};
  }

  try {
    const issues = await runCommand(opts);
    if (opts.exitCode && issues.length > 0) process.exit(EXIT_ISSUES);
    process.exit(EXIT_OK);
  } catch (error) {
    err(`${c.red('Analysis failed:')} ${error?.message || error}`);
    process.exit(EXIT_ERROR);
  }
}

main();
