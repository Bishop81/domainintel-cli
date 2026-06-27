const dns = require('dns');
const util = require('util');
const { logError } = require('../utils/errorLogger');

// Promisify DNS functions
const resolveTxt = util.promisify(dns.resolveTxt);

/**
 * Analyze domain reputation
 * @param {string} domain - The domain to analyze
 * @returns {Promise<Object>} - The reputation analysis
 */
async function analyzeReputation(domain) {
  try {
    // Run all reputation checks in parallel
    const [dnsblResults, spamhausResults, googleSafeBrowsing] = await Promise.allSettled([
      checkDnsblLists(domain),
      checkSpamhaus(domain),
      checkGoogleSafeBrowsing(domain)
    ]);
    
    // Combine results
    const results = {
      dnsbl: dnsblResults.status === 'fulfilled' ? dnsblResults.value : { error: 'DNSBL check failed' },
      spamhaus: spamhausResults.status === 'fulfilled' ? spamhausResults.value : { error: 'Spamhaus check failed' },
      safeBrowsing: googleSafeBrowsing.status === 'fulfilled' ? googleSafeBrowsing.value : { error: 'Safe Browsing check failed' },
      reputationScore: 0
    };
    
    // Calculate overall reputation score
    results.reputationScore = calculateReputationScore(results);
    
    return results;
  } catch (error) {
    logError(error, { domain, service: 'Reputation' });
    return {
      error: `Reputation analysis failed: ${error.message}`,
      reputationScore: 0
    };
  }
}

/**
 * Check domain against common DNSBL lists
 * @param {string} domain - The domain to check
 * @returns {Promise<Object>} - DNSBL check results
 */
async function checkDnsblLists(domain) {
  // Common DNSBL lists for domains
  const dnsblLists = [
    'dbl.spamhaus.org',
    'uribl.spamhaus.org',
    'multi.surbl.org',
    'dnsbl.sorbs.net'
  ];
  
  try {
    const results = {
      listed: false,
      detections: []
    };
    
    // Check each DNSBL list
    const checkPromises = dnsblLists.map(async (dnsbl) => {
      try {
        // Construct the lookup domain
        const lookupDomain = `${domain}.${dnsbl}`;
        
        // Try to resolve the domain
        await util.promisify(dns.resolve4)(lookupDomain);
        
        // If we get here, the domain is listed
        results.listed = true;
        results.detections.push({
          list: dnsbl,
          listed: true
        });
      } catch (error) {
        // Domain not listed (expected error)
        if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
          results.detections.push({
            list: dnsbl,
            listed: false
          });
        } else {
          // Unexpected error
          results.detections.push({
            list: dnsbl,
            listed: false,
            error: error.message
          });
        }
      }
    });
    
    // Wait for all checks to complete
    await Promise.all(checkPromises);
    
    return results;
  } catch (error) {
    return {
      listed: false,
      detections: [],
      error: error.message
    };
  }
}

/**
 * Check domain against Spamhaus ZEN
 * @param {string} domain - The domain to check
 * @returns {Promise<Object>} - Spamhaus check results
 */
async function checkSpamhaus(domain) {
  try {
    // Try to resolve IP addresses for the domain
    const resolve4 = util.promisify(dns.resolve4);
    const ipAddresses = await resolve4(domain).catch(() => []);
    
    if (ipAddresses.length === 0) {
      return {
        listed: false,
        message: 'No IP addresses found for domain'
      };
    }
    
    // Check the first IP address against Spamhaus ZEN
    const ip = ipAddresses[0];
    const reversedIp = ip.split('.').reverse().join('.');
    const lookupDomain = `${reversedIp}.zen.spamhaus.org`;
    
    try {
      // Try to resolve the lookup domain
      await util.promisify(dns.resolve4)(lookupDomain);
      
      // If we get here, the IP is listed
      return {
        listed: true,
        message: 'Domain IP is listed in Spamhaus ZEN'
      };
    } catch (error) {
      // IP not listed (expected error)
      if (error.code === 'ENOTFOUND' || error.code === 'ENODATA') {
        return {
          listed: false,
          message: 'Domain IP is not listed in Spamhaus ZEN'
        };
      } else {
        // Unexpected error
        return {
          listed: false,
          message: 'Spamhaus check failed',
          error: error.message
        };
      }
    }
  } catch (error) {
    return {
      listed: false,
      message: 'Spamhaus check failed',
      error: error.message
    };
  }
}

/**
 * Check domain against Google Safe Browsing
 * Note: This is a mock implementation. In a real application,
 * you would use the Google Safe Browsing API with an API key.
 * @param {string} domain - The domain to check
 * @returns {Promise<Object>} - Safe Browsing check results
 */
async function checkGoogleSafeBrowsing(domain) {
  // This is a mock implementation
  // In a real application, you would use the Google Safe Browsing API
  return {
    safe: true,
    message: 'Domain not found in Google Safe Browsing (mock check)'
  };
}

/**
 * Calculate overall reputation score
 * @param {Object} results - The reputation check results
 * @returns {number} - Reputation score (0-100)
 */
function calculateReputationScore(results) {
  let score = 100; // Start with perfect score
  
  // Deduct points for DNSBL listings
  if (results.dnsbl.listed) {
    // Deduct 20 points for each listing
    const listingCount = results.dnsbl.detections.filter(d => d.listed).length;
    score -= listingCount * 20;
  }
  
  // Deduct points for Spamhaus listing
  if (results.spamhaus.listed) {
    score -= 30;
  }
  
  // Deduct points for Google Safe Browsing
  if (results.safeBrowsing.safe === false) {
    score -= 50;
  }
  
  // Ensure score is between 0 and 100
  return Math.max(0, Math.min(100, score));
}

module.exports = { analyzeReputation }; 