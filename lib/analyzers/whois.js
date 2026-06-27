const whois = require('whois');
const util = require('util');
const { logError } = require('../utils/errorLogger');

// Promisify the whois.lookup function
const whoisQuery = util.promisify(whois.lookup);

/**
 * Analyze WHOIS data for a domain
 * @param {string} domain - The domain to analyze
 * @returns {Promise<Object>} - The WHOIS data
 */
async function analyzeWhois(domain) {
  try {
    // Perform WHOIS lookup
    const whoisData = await whoisQuery(domain);
    
    // Parse the raw WHOIS data
    const parsedData = {
      registrar: extractRegistrar(whoisData),
      creationDate: extractCreationDate(whoisData),
      expirationDate: extractExpirationDate(whoisData),
      updatedDate: extractUpdatedDate(whoisData),
      privacyEnabled: checkPrivacyEnabled(whoisData),
      registrantCountry: extractRegistrantCountry(whoisData),
      rawData: whoisData
    };
    
    return parsedData;
  } catch (error) {
    logError(error, { domain, service: 'WHOIS' });
    throw new Error(`WHOIS lookup failed: ${error.message}`);
  }
}

/**
 * Extract registrar from WHOIS data
 * @param {string} whoisData - The raw WHOIS data
 * @returns {string|null} - The registrar name
 */
function extractRegistrar(whoisData) {
  // Common patterns for registrar information
  const patterns = [
    /Registrar:\s*(.+?)(?:\n|$)/i,
    /Registrar Name:\s*(.+?)(?:\n|$)/i,
    /Sponsoring Registrar:\s*(.+?)(?:\n|$)/i,
    /registrar:\s*(.+?)(?:\n|$)/i
  ];
  
  for (const pattern of patterns) {
    const match = whoisData.match(pattern);
    if (match && match[1] && match[1].trim()) {
      return match[1].trim();
    }
  }
  
  return null;
}

/**
 * Extract creation date from WHOIS data
 * @param {string} whoisData - The raw WHOIS data
 * @returns {string|null} - The creation date
 */
function extractCreationDate(whoisData) {
  // Common patterns for creation date
  const patterns = [
    /Creation Date:\s*(.+?)(?:\n|$)/i,
    /Created on:\s*(.+?)(?:\n|$)/i,
    /Created Date:\s*(.+?)(?:\n|$)/i,
    /Registration Date:\s*(.+?)(?:\n|$)/i,
    /created:\s*(.+?)(?:\n|$)/i,
    /Domain Registration Date:\s*(.+?)(?:\n|$)/i
  ];
  
  for (const pattern of patterns) {
    const match = whoisData.match(pattern);
    if (match && match[1] && match[1].trim()) {
      return formatDate(match[1].trim());
    }
  }
  
  return null;
}

/**
 * Extract expiration date from WHOIS data
 * @param {string} whoisData - The raw WHOIS data
 * @returns {string|null} - The expiration date
 */
function extractExpirationDate(whoisData) {
  // Common patterns for expiration date
  const patterns = [
    /Expiration Date:\s*(.+?)(?:\n|$)/i,
    /Registry Expiry Date:\s*(.+?)(?:\n|$)/i,
    /Expiry Date:\s*(.+?)(?:\n|$)/i,
    /Expires on:\s*(.+?)(?:\n|$)/i,
    /expires:\s*(.+?)(?:\n|$)/i,
    /Domain Expiration Date:\s*(.+?)(?:\n|$)/i
  ];
  
  for (const pattern of patterns) {
    const match = whoisData.match(pattern);
    if (match && match[1] && match[1].trim()) {
      return formatDate(match[1].trim());
    }
  }
  
  return null;
}

/**
 * Extract updated date from WHOIS data
 * @param {string} whoisData - The raw WHOIS data
 * @returns {string|null} - The updated date
 */
function extractUpdatedDate(whoisData) {
  // Common patterns for updated date
  const patterns = [
    /Updated Date:\s*(.+?)(?:\n|$)/i,
    /Last Modified:\s*(.+?)(?:\n|$)/i,
    /Last Updated on:\s*(.+?)(?:\n|$)/i,
    /Last updated:\s*(.+?)(?:\n|$)/i,
    /modified:\s*(.+?)(?:\n|$)/i
  ];
  
  for (const pattern of patterns) {
    const match = whoisData.match(pattern);
    if (match && match[1] && match[1].trim()) {
      return formatDate(match[1].trim());
    }
  }
  
  return null;
}

/**
 * Check if privacy protection is enabled
 * @param {string} whoisData - The raw WHOIS data
 * @returns {boolean} - Whether privacy protection is enabled
 */
function checkPrivacyEnabled(whoisData) {
  // Common patterns for privacy protection
  const privacyPatterns = [
    /privacy/i,
    /private registration/i,
    /proxy/i,
    /redacted for privacy/i,
    /withheld for privacy/i,
    /protected by/i,
    /contact information is protected/i
  ];
  
  // Common patterns for registrant information that would indicate no privacy
  const noPrivacyPatterns = [
    /Registrant Name:\s*(?!privacy|private|proxy|redacted|withheld|protected)(.+?)(?:\n|$)/i,
    /Registrant Organization:\s*(?!privacy|private|proxy|redacted|withheld|protected)(.+?)(?:\n|$)/i,
    /Registrant Email:\s*(?!privacy|private|proxy|redacted|withheld|protected)(.+?)(?:\n|$)/i
  ];
  
  // Check for privacy indicators
  for (const pattern of privacyPatterns) {
    if (pattern.test(whoisData)) {
      return true;
    }
  }
  
  // Check for non-privacy indicators
  for (const pattern of noPrivacyPatterns) {
    const match = whoisData.match(pattern);
    if (match && match[1] && match[1].trim() && !privacyPatterns.some(p => p.test(match[1]))) {
      return false;
    }
  }
  
  // Default to true if we can't determine
  return true;
}

/**
 * Extract registrant country from WHOIS data
 * @param {string} whoisData - The raw WHOIS data
 * @returns {string|null} - The registrant country
 */
function extractRegistrantCountry(whoisData) {
  // Common patterns for registrant country
  const patterns = [
    /Registrant Country:\s*(.+?)(?:\n|$)/i,
    /Registry Registrant Country:\s*(.+?)(?:\n|$)/i,
    /Registrant Country\/Economy:\s*(.+?)(?:\n|$)/i,
    /country:\s*(.+?)(?:\n|$)/i
  ];
  
  for (const pattern of patterns) {
    const match = whoisData.match(pattern);
    if (match && match[1] && match[1].trim()) {
      return match[1].trim();
    }
  }
  
  return null;
}

/**
 * Format date string to ISO format if possible
 * @param {string} dateStr - The date string to format
 * @returns {string} - The formatted date string
 */
function formatDate(dateStr) {
  try {
    const date = new Date(dateStr);
    if (!isNaN(date.getTime())) {
      return date.toISOString().split('T')[0];
    }
  } catch (error) {
    // If parsing fails, return the original string
  }
  
  return dateStr;
}

module.exports = { analyzeWhois }; 