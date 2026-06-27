const https = require('https');
const tls = require('tls');
const { logError } = require('../utils/errorLogger');

/**
 * Analyze SSL/TLS certificate for a domain
 * @param {string} domain - The domain to analyze
 * @returns {Promise<Object>} - The SSL/TLS certificate information
 */
async function analyzeSsl(domain) {
  console.log(`Starting SSL analysis for domain: ${domain}`);
  
  try {
    // Get SSL certificate
    const cert = await getCertificate(domain);
    
    if (!cert) {
      console.log(`No SSL certificate found for domain: ${domain}`);
      return {
        valid: false,
        error: 'No SSL certificate found'
      };
    }

    // Log certificate details for debugging
    console.log(`Certificate for ${domain}:`, JSON.stringify(cert, null, 2));
    
    // Parse certificate information
    const certInfo = {
      valid: true,
      issuer: parseCertificateIssuer(cert.issuer),
      subject: parseCertificateSubject(cert.subject),
      validFrom: new Date(cert.valid_from).toISOString(),
      validTo: new Date(cert.valid_to).toISOString(),
      daysRemaining: calculateDaysRemaining(cert.valid_to),
      serialNumber: cert.serialNumber,
      fingerprint: cert.fingerprint,
      version: cert.version,
      subjectAlternativeNames: parseSubjectAltNames(cert.subjectaltname),
      securityDetails: await checkSecurityDetails(domain)
    };
    
    // Log parsed certificate info
    console.log(`Parsed certificate info for ${domain}:`, JSON.stringify(certInfo, null, 2));
    
    // Add certificate warnings
    certInfo.warnings = checkCertificateWarnings(certInfo);
    
    return certInfo;
  } catch (error) {
    console.error(`SSL analysis error for ${domain}:`, error);
    logError(error, { domain, service: 'SSL' });
    return {
      valid: false,
      error: `SSL analysis failed: ${error.message}`
    };
  }
}

/**
 * Get SSL certificate for a domain
 * @param {string} domain - The domain to check
 * @returns {Promise<Object>} - The certificate object
 */
function getCertificate(domain) {
  return new Promise((resolve, reject) => {
    const options = {
      host: domain,
      port: 443,
      method: 'GET',
      path: '/',
      rejectUnauthorized: false, // Allow self-signed certificates
      timeout: 10000 // 10 second timeout
    };
    
    const req = https.request(options, (res) => {
      const cert = res.socket.getPeerCertificate();
      
      // Check if certificate is empty
      if (Object.keys(cert).length < 1) {
        return reject(new Error('No certificate found'));
      }
      
      resolve(cert);
    });
    
    req.on('error', (error) => {
      reject(error);
    });
    
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Request timed out'));
    });
    
    req.end();
  });
}

/**
 * Parse certificate issuer information
 * @param {Object} issuer - The certificate issuer object
 * @returns {Object} - Parsed issuer information
 */
function parseCertificateIssuer(issuer) {
  if (!issuer) return null;
  
  return {
    organization: issuer.O || issuer.organization || null,
    commonName: issuer.CN || issuer.commonName || null,
    country: issuer.C || issuer.country || null,
    state: issuer.ST || issuer.state || null,
    locality: issuer.L || issuer.locality || null
  };
}

/**
 * Parse certificate subject information
 * @param {Object} subject - The certificate subject object
 * @returns {Object} - Parsed subject information
 */
function parseCertificateSubject(subject) {
  if (!subject) return null;
  
  return {
    organization: subject.O || subject.organization || null,
    commonName: subject.CN || subject.commonName || null,
    country: subject.C || subject.country || null,
    state: subject.ST || subject.state || null,
    locality: subject.L || subject.locality || null
  };
}

/**
 * Parse Subject Alternative Names from certificate
 * @param {string} subjectAltName - The subjectAltName string
 * @returns {Array} - List of alternative names
 */
function parseSubjectAltNames(subjectAltName) {
  if (!subjectAltName) return [];
  
  // Extract DNS names from the subjectAltName string
  const dnsNames = [];
  const matches = subjectAltName.match(/DNS:([^,]+)/g);
  
  if (matches) {
    matches.forEach(match => {
      dnsNames.push(match.replace('DNS:', '').trim());
    });
  }
  
  return dnsNames;
}

/**
 * Calculate days remaining until certificate expiration
 * @param {string} validTo - The expiration date string
 * @returns {number} - Days remaining
 */
function calculateDaysRemaining(validTo) {
  const expirationDate = new Date(validTo);
  const currentDate = new Date();
  
  // Calculate difference in milliseconds
  const diffMs = expirationDate - currentDate;
  
  // Convert to days
  return Math.ceil(diffMs / (1000 * 60 * 60 * 24));
}

/**
 * Check for certificate warnings
 * @param {Object} certInfo - The certificate information
 * @returns {Array} - List of warnings
 */
function checkCertificateWarnings(certInfo) {
  const warnings = [];
  
  // Check for expiration
  if (certInfo.daysRemaining < 0) {
    warnings.push({
      type: 'EXPIRED',
      severity: 'high',
      message: 'SSL certificate has expired'
    });
  } else if (certInfo.daysRemaining < 30) {
    warnings.push({
      type: 'EXPIRING_SOON',
      severity: 'medium',
      message: `SSL certificate will expire in ${certInfo.daysRemaining} days`
    });
  }
  
  // Check for weak security
  if (certInfo.securityDetails) {
    if (!certInfo.securityDetails.secureProtocol) {
      warnings.push({
        type: 'WEAK_PROTOCOL',
        severity: 'high',
        message: 'SSL certificate uses a weak protocol'
      });
    }
    
    if (!certInfo.securityDetails.secureRenegotiation) {
      warnings.push({
        type: 'INSECURE_RENEGOTIATION',
        severity: 'medium',
        message: 'SSL certificate does not support secure renegotiation'
      });
    }
  }
  
  return warnings;
}

/**
 * Check security details of the SSL connection
 * @param {string} domain - The domain to check
 * @returns {Promise<Object>} - Security details
 */
async function checkSecurityDetails(domain) {
  return new Promise((resolve) => {
    try {
      const socket = tls.connect({
        host: domain,
        port: 443,
        rejectUnauthorized: false,
        timeout: 10000
      }, () => {
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const secureRenegotiation = socket.isSessionReused();
        
        socket.end();
        
        resolve({
          protocol,
          cipher,
          secureRenegotiation,
          secureProtocol: isSecureProtocol(protocol)
        });
      });
      
      socket.on('error', () => {
        resolve({
          protocol: null,
          cipher: null,
          secureRenegotiation: false,
          secureProtocol: false
        });
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        resolve({
          protocol: null,
          cipher: null,
          secureRenegotiation: false,
          secureProtocol: false
        });
      });
    } catch (error) {
      resolve({
        protocol: null,
        cipher: null,
        secureRenegotiation: false,
        secureProtocol: false
      });
    }
  });
}

/**
 * Check if the protocol is considered secure
 * @param {string} protocol - The TLS protocol
 * @returns {boolean} - Whether the protocol is secure
 */
function isSecureProtocol(protocol) {
  if (!protocol) return false;
  
  // TLS 1.2 and above are considered secure
  const secureProtocols = ['TLSv1.2', 'TLSv1.3'];
  return secureProtocols.includes(protocol);
}

module.exports = { analyzeSsl }; 