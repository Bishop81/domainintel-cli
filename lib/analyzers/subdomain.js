const dns = require('dns');
const util = require('util');
const https = require('https');
const { logError } = require('../utils/errorLogger');

const resolveCname = util.promisify(dns.resolveCname);
const resolve4 = util.promisify(dns.resolve4);
const resolve6 = util.promisify(dns.resolve6);

/**
 * Query Certificate Transparency logs via crt.sh
 * @param {string} domain - The domain to search
 * @returns {Promise<Array>} - Array of certificate records
 */
async function queryCertificateTransparency(domain) {
  return new Promise((resolve, reject) => {
    const url = `https://crt.sh/?q=%.${domain}&output=json`;

    https.get(url, { timeout: 10000 }, (res) => {
      let data = '';

      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          if (res.statusCode === 200) {
            const certificates = JSON.parse(data);
            resolve(certificates);
          } else {
            resolve([]);
          }
        } catch (error) {
          logError(error, { domain, service: 'CertificateTransparency' });
          resolve([]);
        }
      });
    }).on('error', (error) => {
      logError(error, { domain, service: 'CertificateTransparency' });
      resolve([]);
    }).on('timeout', () => {
      logError(new Error('CT log query timeout'), { domain, service: 'CertificateTransparency' });
      resolve([]);
    });
  });
}

/**
 * Extract unique subdomains from certificate data
 * @param {Array} certificates - Certificate records from crt.sh
 * @param {string} baseDomain - The base domain to filter
 * @returns {Set} - Set of unique subdomains
 */
function extractSubdomains(certificates, baseDomain) {
  const subdomains = new Set();

  for (const cert of certificates) {
    if (!cert.name_value) continue;

    // name_value can contain multiple domains separated by newlines
    const domains = cert.name_value.split('\n');

    for (let domain of domains) {
      domain = domain.trim().toLowerCase();

      // Skip wildcards and the base domain itself
      if (domain.startsWith('*.')) continue;
      if (domain === baseDomain) continue;
      if (domain === `www.${baseDomain}`) continue;

      // Only include subdomains of the base domain
      if (domain.endsWith(`.${baseDomain}`)) {
        subdomains.add(domain);
      }
    }
  }

  return subdomains;
}

/**
 * Check DNS records for a subdomain
 * @param {string} subdomain - The subdomain to check
 * @returns {Promise<Object>} - DNS information for the subdomain
 */
async function checkSubdomainDns(subdomain) {
  const result = {
    subdomain,
    cname: null,
    ipv4: [],
    ipv6: [],
    active: false
  };

  try {
    // Check for CNAME
    try {
      const cnames = await resolveCname(subdomain);
      if (cnames && cnames.length > 0) {
        result.cname = cnames[0];
        result.active = true;
      }
    } catch (error) {
      // No CNAME record, continue to check A/AAAA
    }

    // Check for A records
    try {
      const ipv4 = await resolve4(subdomain);
      if (ipv4 && ipv4.length > 0) {
        result.ipv4 = ipv4;
        result.active = true;
      }
    } catch (error) {
      // No A records
    }

    // Check for AAAA records
    try {
      const ipv6 = await resolve6(subdomain);
      if (ipv6 && ipv6.length > 0) {
        result.ipv6 = ipv6;
        result.active = true;
      }
    } catch (error) {
      // No AAAA records
    }
  } catch (error) {
    logError(error, { subdomain, service: 'SubdomainDNS' });
  }

  return result;
}

/**
 * Discover and analyze subdomains for a domain
 * @param {string} domain - The domain to analyze
 * @returns {Promise<Object>} - Subdomain discovery results
 */
async function analyzeSubdomains(domain) {
  try {
    const startTime = Date.now();

    // Query Certificate Transparency logs
    const certificates = await queryCertificateTransparency(domain);

    // Extract unique subdomains
    const subdomains = extractSubdomains(certificates, domain);

    // Check DNS for each subdomain (limit concurrency to avoid overwhelming DNS)
    const subdomainList = Array.from(subdomains);
    const batchSize = 5;
    const results = [];

    for (let i = 0; i < subdomainList.length; i += batchSize) {
      const batch = subdomainList.slice(i, i + batchSize);
      const batchResults = await Promise.all(
        batch.map(subdomain => checkSubdomainDns(subdomain))
      );
      results.push(...batchResults);
    }

    // Filter to only active subdomains
    const activeSubdomains = results.filter(result => result.active);

    // Separate CNAMEs from direct records
    const cnameRecords = activeSubdomains.filter(result => result.cname);
    const directRecords = activeSubdomains.filter(result => !result.cname && (result.ipv4.length > 0 || result.ipv6.length > 0));

    return {
      success: true,
      totalFound: subdomains.size,
      activeCount: activeSubdomains.length,
      cnameCount: cnameRecords.length,
      directCount: directRecords.length,
      subdomains: activeSubdomains,
      cnameRecords,
      directRecords,
      duration: Date.now() - startTime
    };
  } catch (error) {
    logError(error, { domain, service: 'SubdomainAnalyzer' });
    return {
      success: false,
      error: error.message,
      totalFound: 0,
      activeCount: 0,
      cnameCount: 0,
      directCount: 0,
      subdomains: [],
      cnameRecords: [],
      directRecords: []
    };
  }
}

module.exports = {
  analyzeSubdomains,
  queryCertificateTransparency,
  extractSubdomains,
  checkSubdomainDns
};
