// Generates reference_vectors.json: links as the reference formulas build them.
//
//   node internal/links/testdata/gen_vectors.mjs
//
// The formulas below are copied from the design spec, section 4 (the link
// contract), without any cleanup, on purpose: this file is the independent
// reference the Go link builder (internal/links) is checked against, byte for
// byte. Node.js built-ins only, no dependencies. The output is deterministic,
// so a second run must leave the committed JSON unchanged. Do not edit the JSON
// by hand; change the input lists here and run the script again.
//
// The formulas (spec section 4):
//
//   tg://proxy
//     server = encodeURIComponent(node.domain || node.ip)
//     port   = proxy.listenPort || NGINX_PORT
//     secret = 'ee' + proxy.secret + Buffer.from(proxy.domain, 'utf-8').toString('hex')
//
//   WEB
//     https://t.me/webproxy?server=encodeURIComponent(proxy.domain)&secret=(dd?)secret

import { writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

// Only documentation addresses and reserved domains: 192.0.2.0/24,
// 198.51.100.0/24, 203.0.113.0/24, 2001:db8::/32, example.com, *.example.

// node.domain || node.ip: what goes into server=.
const HOSTS = [
  '203.0.113.10', // IPv4
  '2001:db8::10', // IPv6: ':' must become %3A
  'proxy.example.com', // plain domain
  'Node-1.Example.COM', // mixed case: stored as is, never lowercased
  'пример.example', // unicode: percent-encoded UTF-8 bytes, no punycode
  "x!'()*~y.example", // the characters encodeURIComponent leaves alone
  'a b+c&d=e#f/g?h@i$j,k;l:m%n.example', // everything else is escaped
];

// proxy.domain: the fake-TLS SNI domain and the WEB proxy domain.
const DOMAINS = [
  'proxy.example.com',
  'www.example.com',
  'WWW.Example.COM', // case is kept in the bytes that get hex-encoded
  'пример.example', // multi-byte UTF-8 in hex(domain)
];

// proxy.secret: stored as is, so the case must survive untouched.
const SECRETS = [
  '000102030405060708090a0b0c0d0e0f', // lowercase hex
  'ABCDEF0123456789ABCDEF0123456789', // UPPERCASE hex
];

// proxy.listenPort || NGINX_PORT.
const PORTS = [443, 8443];

function tgLink(host, port, secret, domain) {
  const server = encodeURIComponent(host);
  const fullSecret = 'ee' + secret + Buffer.from(domain, 'utf-8').toString('hex');
  return `tg://proxy?server=${server}&port=${port}&secret=${fullSecret}`;
}

function webHttpsLink(domain, secret, dd) {
  return `https://t.me/webproxy?server=${encodeURIComponent(domain)}&secret=${dd ? 'dd' : ''}${secret}`;
}

// Every value in the file is made up, but the links carry "secret=<hex>" and
// would trip the generic-api-key rule of gitleaks: .gitleaks.toml leaves the
// file out of the scan by its path.

const vectors = [];
for (const host of HOSTS) {
  for (const domain of DOMAINS) {
    for (const secret of SECRETS) {
      for (const port of PORTS) {
        vectors.push({
          host,
          port,
          secret,
          domain,
          tg: tgLink(host, port, secret, domain),
          web_https: webHttpsLink(domain, secret, false), // WEB, plain secret
          web_https_dd: webHttpsLink(domain, secret, true), // WEB, dd secret
        });
      }
    }
  }
}

// One vector per line keeps the file greppable and its diffs readable.
const json = '[\n' + vectors.map((v) => '  ' + JSON.stringify(v)).join(',\n') + '\n]\n';
const out = join(dirname(fileURLToPath(import.meta.url)), 'reference_vectors.json');
writeFileSync(out, json);
console.log(`wrote ${vectors.length} vectors to ${out}`);
