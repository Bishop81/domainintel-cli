const dns = require('dns');
const util = require('util');
const { logError } = require('../utils/errorLogger');

// Promisify DNS functions
const resolve4 = util.promisify(dns.resolve4);
const resolve6 = util.promisify(dns.resolve6);
const resolveMx = util.promisify(dns.resolveMx);
const resolveTxt = util.promisify(dns.resolveTxt);
const resolveNs = util.promisify(dns.resolveNs);
const resolveCname = util.promisify(dns.resolveCname);
const resolveSoa = util.promisify(dns.resolveSoa);

/**
 * Analyze DNS records for a domain
 * @param {string} domain - The domain to analyze
 * @returns {Promise<Object>} - The DNS records
 */
async function analyzeDns(domain) {
  try {
    // Initialize results object
    const results = {
      a: [],
      aaaa: [],
      mx: [],
      txt: [],
      ns: [],
      cname: [],
      soa: null,
      hasDmarc: false,
      hasSpf: false,
      hasMx: false
    };
    
    // Fetch all DNS records in parallel
    const [aRecords, aaaaRecords, mxRecords, txtRecords, nsRecords, cnameRecords, soaRecord] = 
      await Promise.allSettled([
        resolve4(domain).catch(() => []),
        resolve6(domain).catch(() => []),
        resolveMx(domain).catch(() => []),
        resolveTxt(domain).catch(() => []),
        resolveNs(domain).catch(() => []),
        resolveCname(domain).catch(() => []),
        resolveSoa(domain).catch(() => null)
      ]);
    
    // Process A records
    if (aRecords.status === 'fulfilled') {
      results.a = aRecords.value;
    }
    
    // Process AAAA records
    if (aaaaRecords.status === 'fulfilled') {
      results.aaaa = aaaaRecords.value;
    }
    
    // Process MX records
    if (mxRecords.status === 'fulfilled') {
      results.mx = mxRecords.value;
      results.hasMx = mxRecords.value.length > 0;
    }
    
    // Process TXT records
    if (txtRecords.status === 'fulfilled') {
      // Flatten TXT record arrays
      results.txt = txtRecords.value.map(record => record.join(''));
      
      // Check for SPF and DMARC records
      results.hasSpf = txtRecords.value.some(record => 
        record.join('').toLowerCase().startsWith('v=spf1')
      );
      
      // Try to find DMARC record
      try {
        const dmarcRecords = await resolveTxt(`_dmarc.${domain}`).catch(() => []);
        results.hasDmarc = dmarcRecords.some(record => 
          record.join('').toLowerCase().startsWith('v=dmarc1')
        );
      } catch (error) {
        // DMARC record not found
        results.hasDmarc = false;
      }
    }
    
    // Process NS records
    if (nsRecords.status === 'fulfilled') {
      results.ns = nsRecords.value;
    }
    
    // Process CNAME records
    if (cnameRecords.status === 'fulfilled') {
      results.cname = cnameRecords.value;
    }
    
    // Process SOA record
    if (soaRecord.status === 'fulfilled') {
      results.soa = soaRecord.value;
    }
    
    return results;
  } catch (error) {
    logError(error, { domain, service: 'DNS' });
    throw new Error(`DNS lookup failed: ${error.message}`);
  }
}

/**
 * Check if a domain has CAA records
 * @param {string} domain - The domain to check
 * @returns {Promise<Object>} - CAA record information
 */
async function checkCaaRecords(domain) {
  try {
    // Try to resolve CAA records
    const resolveCaa = util.promisify(dns.resolveCaa);
    const caaRecords = await resolveCaa(domain).catch(() => []);
    
    return {
      hasCaa: caaRecords.length > 0,
      records: caaRecords
    };
  } catch (error) {
    // CAA records not supported or not found
    return {
      hasCaa: false,
      records: []
    };
  }
}

/**
 * Check for common DNS misconfigurations
 * @param {Object} dnsRecords - The DNS records
 * @returns {Object} - Misconfiguration warnings
 */
function checkDnsMisconfigurations(dnsRecords) {
  const warnings = [];
  
  // Check for missing SPF record
  if (!dnsRecords.hasSpf && dnsRecords.hasMx) {
    warnings.push({
      type: 'SPF',
      severity: 'medium',
      message: 'Missing SPF record. This can lead to email deliverability issues and increased risk of spoofing.'
    });
  }
  
  // Check for missing DMARC record
  if (!dnsRecords.hasDmarc && dnsRecords.hasMx) {
    warnings.push({
      type: 'DMARC',
      severity: 'medium',
      message: 'Missing DMARC record. This can lead to email deliverability issues and increased risk of spoofing.'
    });
  }
  
  // Check for missing MX records
  if (!dnsRecords.hasMx && dnsRecords.a.length > 0) {
    warnings.push({
      type: 'MX',
      severity: 'low',
      message: 'No MX records found. If this domain is used for email, it may cause email delivery issues.'
    });
  }
  
  // Check for missing A records
  if (dnsRecords.a.length === 0 && dnsRecords.aaaa.length === 0) {
    warnings.push({
      type: 'A/AAAA',
      severity: 'high',
      message: 'No A or AAAA records found. The domain does not resolve to any IP address.'
    });
  }
  
  return {
    hasWarnings: warnings.length > 0,
    warnings
  };
}

module.exports = {
  analyzeDns,
  checkCaaRecords,
  checkDnsMisconfigurations
}; 