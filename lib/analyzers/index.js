const { validateDomain } = require('../utils/validator');
const { logError } = require('../utils/errorLogger');
const domainQueue = require('../utils/queue');
const { analyzeWhois } = require('./whois');
const { analyzeDns, checkCaaRecords, checkDnsMisconfigurations } = require('./dns');
const { analyzeSsl } = require('./ssl');
const { analyzeHeaders } = require('./headers');
const { analyzeReputation } = require('./reputation');
const { analyzeSubdomains } = require('./subdomain');

/**
 * Analyze a domain using all available analyzers
 * @param {string} domain - The domain to analyze
 * @param {Object} options - Analysis options
 * @returns {Promise<Object>} - The analysis results
 */
async function analyzeDomain(domain, options = {}) {
  // Validate domain
  if (!validateDomain(domain)) {
    throw new Error('Invalid domain format');
  }
  
  // Normalize domain (remove protocol, path, etc.)
  const normalizedDomain = normalizeDomain(domain);
  
  // Create a unique ID for this analysis
  const analysisId = `${normalizedDomain}_${Date.now()}`;
  
  // Add the analysis job to the queue
  return domainQueue.enqueue(analysisId, async () => {
    try {
      const startTime = Date.now();
      
      // Run all analyzers in parallel
      const [whoisResults, dnsResults, sslResults, headersResults, reputationResults, subdomainResults] =
        await Promise.allSettled([
          analyzeWhois(normalizedDomain),
          analyzeDns(normalizedDomain),
          analyzeSsl(normalizedDomain),
          analyzeHeaders(normalizedDomain),
          analyzeReputation(normalizedDomain),
          analyzeSubdomains(normalizedDomain)
        ]);
      
      // Process DNS results further if available
      let dnsWarnings = { hasWarnings: false, warnings: [] };
      let caaResults = { hasCaa: false, records: [] };
      
      if (dnsResults.status === 'fulfilled') {
        dnsWarnings = checkDnsMisconfigurations(dnsResults.value);
        caaResults = await checkCaaRecords(normalizedDomain).catch(() => ({ hasCaa: false, records: [] }));
      }
      
      // Calculate overall security score
      const securityScore = calculateSecurityScore({
        dns: dnsResults.status === 'fulfilled' ? dnsResults.value : null,
        ssl: sslResults.status === 'fulfilled' ? sslResults.value : null,
        headers: headersResults.status === 'fulfilled' ? headersResults.value : null,
        reputation: reputationResults.status === 'fulfilled' ? reputationResults.value : null,
        dnsWarnings,
        caaResults
      });
      
      // Combine all results
      const results = {
        domain: normalizedDomain,
        analysisId,
        timestamp: new Date().toISOString(),
        duration: Date.now() - startTime,
        securityScore,
        whois: whoisResults.status === 'fulfilled' ? whoisResults.value : { error: whoisResults.reason.message },
        dns: dnsResults.status === 'fulfilled' ? {
          ...dnsResults.value,
          warnings: dnsWarnings.warnings,
          caa: caaResults
        } : { error: dnsResults.reason.message },
        ssl: sslResults.status === 'fulfilled' ? sslResults.value : { error: sslResults.reason.message },
        headers: headersResults.status === 'fulfilled' ? headersResults.value : { error: headersResults.reason.message },
        reputation: reputationResults.status === 'fulfilled' ? reputationResults.value : { error: reputationResults.reason.message },
        subdomains: subdomainResults.status === 'fulfilled' ? subdomainResults.value : { error: subdomainResults.reason?.message || 'Subdomain analysis failed' }
      };
      
      return results;
    } catch (error) {
      logError(error, { domain: normalizedDomain, service: 'DomainAnalyzer' });
      throw new Error(`Domain analysis failed: ${error.message}`);
    }
  });
}

/**
 * Normalize a domain by removing protocol, path, etc.
 * @param {string} domain - The domain to normalize
 * @returns {string} - The normalized domain
 */
function normalizeDomain(domain) {
  // Remove protocol
  let normalizedDomain = domain.replace(/^(https?:\/\/)?(www\.)?/i, '');
  
  // Remove path and query parameters
  normalizedDomain = normalizedDomain.split('/')[0];
  
  // Remove port
  normalizedDomain = normalizedDomain.split(':')[0];
  
  return normalizedDomain.toLowerCase();
}

/**
 * Calculate overall security score
 * @param {Object} results - The analysis results
 * @returns {Object} - The security score
 */
function calculateSecurityScore(results) {
  // Define weights for each category
  const weights = {
    ssl: 30,
    headers: 25,
    dns: 20,
    reputation: 25
  };
  
  let totalScore = 0;
  let maxScore = 0;
  const categoryScores = {};
  
  // Calculate SSL score
  if (results.ssl && results.ssl.valid) {
    const sslScore = results.ssl.warnings.length === 0 ? 100 : 
                    (results.ssl.warnings.some(w => w.severity === 'high') ? 30 : 
                     results.ssl.warnings.some(w => w.severity === 'medium') ? 60 : 80);
    
    categoryScores.ssl = sslScore;
    totalScore += sslScore * (weights.ssl / 100);
    maxScore += weights.ssl;
  }
  
  // Calculate headers score
  if (results.headers && results.headers.success) {
    const headersScore = results.headers.securityAnalysis.securityScore.percentage;
    categoryScores.headers = headersScore;
    totalScore += headersScore * (weights.headers / 100);
    maxScore += weights.headers;
  }
  
  // Calculate DNS score
  if (results.dns) {
    let dnsScore = 100;
    
    // Deduct points for DNS warnings
    if (results.dnsWarnings.hasWarnings) {
      const highWarnings = results.dnsWarnings.warnings.filter(w => w.severity === 'high').length;
      const mediumWarnings = results.dnsWarnings.warnings.filter(w => w.severity === 'medium').length;
      const lowWarnings = results.dnsWarnings.warnings.filter(w => w.severity === 'low').length;
      
      dnsScore -= (highWarnings * 30 + mediumWarnings * 15 + lowWarnings * 5);
    }
    
    // Add points for CAA records
    if (results.caaResults.hasCaa) {
      dnsScore += 10;
    }
    
    // Ensure score is between 0 and 100
    dnsScore = Math.max(0, Math.min(100, dnsScore));
    
    categoryScores.dns = dnsScore;
    totalScore += dnsScore * (weights.dns / 100);
    maxScore += weights.dns;
  }
  
  // Calculate reputation score
  if (results.reputation && typeof results.reputation.reputationScore === 'number') {
    const reputationScore = results.reputation.reputationScore;
    categoryScores.reputation = reputationScore;
    totalScore += reputationScore * (weights.reputation / 100);
    maxScore += weights.reputation;
  }
  
  // Calculate overall percentage
  const overallPercentage = maxScore > 0 ? Math.round((totalScore / maxScore) * 100) : 0;
  
  // Determine rating
  let rating;
  if (overallPercentage >= 90) {
    rating = 'A+';
  } else if (overallPercentage >= 80) {
    rating = 'A';
  } else if (overallPercentage >= 70) {
    rating = 'B';
  } else if (overallPercentage >= 60) {
    rating = 'C';
  } else if (overallPercentage >= 50) {
    rating = 'D';
  } else {
    rating = 'F';
  }
  
  return {
    overall: overallPercentage,
    rating,
    categoryScores
  };
}

module.exports = {
  analyzeDomain,
  normalizeDomain
}; 