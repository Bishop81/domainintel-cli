/**
 * Validate domain format
 * @param {string} domain - The domain to validate
 * @returns {boolean} - Whether the domain is valid
 */
function validateDomain(domain) {
  if (!domain || typeof domain !== 'string') {
    return false;
  }
  
  // Basic domain format validation
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
  
  return domainRegex.test(domain);
}

/**
 * Sanitize input to prevent SQL injection and XSS
 * @param {string} input - The input to sanitize
 * @returns {string} - The sanitized input
 */
function sanitizeInput(input) {
  if (!input || typeof input !== 'string') {
    return '';
  }
  
  // Remove potentially dangerous characters
  return input
    .replace(/[<>]/g, '') // Remove < and > to prevent HTML injection
    .replace(/'/g, "''"); // Escape single quotes for SQL safety
}

/**
 * Validate IP address format
 * @param {string} ip - The IP address to validate
 * @returns {boolean} - Whether the IP address is valid
 */
function validateIpAddress(ip) {
  if (!ip || typeof ip !== 'string') {
    return false;
  }
  
  // IPv4 validation
  const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;
  const ipv4Match = ip.match(ipv4Regex);
  
  if (ipv4Match) {
    return ipv4Match.slice(1).every(octet => parseInt(octet, 10) <= 255);
  }
  
  // IPv6 validation (simplified)
  const ipv6Regex = /^([0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$/i;
  return ipv6Regex.test(ip);
}

/**
 * Validate URL format
 * @param {string} url - The URL to validate
 * @returns {boolean} - Whether the URL is valid
 */
function validateUrl(url) {
  if (!url || typeof url !== 'string') {
    return false;
  }
  
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === 'http:' || urlObj.protocol === 'https:';
  } catch (error) {
    return false;
  }
}

module.exports = {
  validateDomain,
  sanitizeInput,
  validateIpAddress,
  validateUrl
}; 