const https = require('https');
const http = require('http');
const { logError } = require('../utils/errorLogger');

/**
 * Analyze HTTP headers for a domain
 * @param {string} domain - The domain to analyze
 * @returns {Promise<Object>} - The HTTP headers analysis
 */
async function analyzeHeaders(domain) {
  try {
    // Check both the bare domain and www subdomain
    const domains = [domain];
    if (!domain.startsWith('www.')) {
      domains.push(`www.${domain}`);
    }
    
    let bestHeaders = {};
    let bestSecurityAnalysis = null;
    let bestRedirects = null;
    
    // Try each domain variant
    for (const domainVariant of domains) {
      try {
        // Get HTTP and HTTPS headers
        const [httpHeaders, httpsHeaders] = await Promise.allSettled([
          getHeaders(domainVariant, false),
          getHeaders(domainVariant, true)
        ]);
        
        // Use HTTPS headers if available, otherwise use HTTP headers
        const headers = httpsHeaders.status === 'fulfilled' ? httpsHeaders.value : 
                       (httpHeaders.status === 'fulfilled' ? httpHeaders.value : {});
        
        if (Object.keys(headers).length === 0) {
          continue;
        }
        
        // Analyze security headers
        const securityAnalysis = analyzeSecurityHeaders(headers);
        const redirects = await checkRedirects(domainVariant);
        
        // If this variant has more security headers, use it as the best result
        if (!bestSecurityAnalysis || 
            Object.values(securityAnalysis.securityHeaders).filter(h => h.present).length > 
            Object.values(bestSecurityAnalysis.securityHeaders).filter(h => h.present).length) {
          bestHeaders = headers;
          bestSecurityAnalysis = securityAnalysis;
          bestRedirects = redirects;
        }
      } catch (error) {
        console.error(`Error analyzing headers for ${domainVariant}:`, error);
        // Continue with the next domain variant
      }
    }
    
    if (Object.keys(bestHeaders).length === 0) {
      return {
        success: false,
        error: 'Could not retrieve headers'
      };
    }
    
    return {
      success: true,
      headers: bestHeaders,
      securityAnalysis: bestSecurityAnalysis,
      redirects: bestRedirects
    };
  } catch (error) {
    logError(error, { domain, service: 'Headers' });
    return {
      success: false,
      error: `Headers analysis failed: ${error.message}`
    };
  }
}

/**
 * Get HTTP headers for a domain
 * @param {string} domain - The domain to check
 * @param {boolean} useHttps - Whether to use HTTPS
 * @returns {Promise<Object>} - The HTTP headers
 */
function getHeaders(domain, useHttps = true) {
  return new Promise((resolve, reject) => {
    const options = {
      host: domain,
      port: useHttps ? 443 : 80,
      method: 'GET', // Changed from HEAD to GET to better handle some servers
      path: '/',
      timeout: 10000, // 10 second timeout
      rejectUnauthorized: false, // Allow self-signed certificates
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
      }
    };
    
    const protocol = useHttps ? https : http;
    
    const req = protocol.request(options, (res) => {
      // Check if we got a redirect
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        try {
          // Parse the redirect URL
          const redirectUrl = new URL(
            res.headers.location.startsWith('http') 
              ? res.headers.location 
              : `${useHttps ? 'https' : 'http'}://${domain}${res.headers.location}`
          );
          
          // Follow the redirect
          getHeadersFromUrl(redirectUrl.href)
            .then(resolve)
            .catch(reject);
        } catch (error) {
          // If we can't parse the URL, just return the current headers
          resolve(res.headers);
        }
      } else {
        // No redirect, return the headers
        resolve(res.headers);
      }
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
 * Get headers from a complete URL
 * @param {string} url - The complete URL to check
 * @returns {Promise<Object>} - The HTTP headers
 */
function getHeadersFromUrl(url) {
  return new Promise((resolve, reject) => {
    try {
      const parsedUrl = new URL(url);
      const protocol = parsedUrl.protocol === 'https:' ? https : http;
      
      const options = {
        host: parsedUrl.hostname,
        port: parsedUrl.port || (parsedUrl.protocol === 'https:' ? 443 : 80),
        method: 'GET',
        path: parsedUrl.pathname + parsedUrl.search,
        timeout: 10000,
        rejectUnauthorized: false,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
      };
      
      const req = protocol.request(options, (res) => {
        // Check if we got another redirect (limit to prevent infinite loops)
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && url !== res.headers.location) {
          try {
            // Parse the redirect URL
            const redirectUrl = new URL(
              res.headers.location.startsWith('http') 
                ? res.headers.location 
                : `${parsedUrl.protocol}//${parsedUrl.host}${res.headers.location}`
            );
            
            // Follow the redirect (but only once more to prevent infinite loops)
            if (redirectUrl.href !== url) {
              getHeadersFromUrl(redirectUrl.href)
                .then(resolve)
                .catch(reject);
              return;
            }
          } catch (error) {
            // If we can't parse the URL, just return the current headers
          }
        }
        
        // No redirect or we've reached our redirect limit, return the headers
        resolve(res.headers);
      });
      
      req.on('error', (error) => {
        reject(error);
      });
      
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timed out'));
      });
      
      req.end();
    } catch (error) {
      reject(error);
    }
  });
}

/**
 * Analyze security headers
 * @param {Object} headers - The HTTP headers
 * @returns {Object} - Security headers analysis
 */
function analyzeSecurityHeaders(headers) {
  // Check for important security headers
  const securityHeaders = {
    'strict-transport-security': checkHeader(headers, 'strict-transport-security'),
    'content-security-policy': checkHeader(headers, 'content-security-policy'),
    'x-content-type-options': checkHeader(headers, 'x-content-type-options'),
    'x-frame-options': checkHeader(headers, 'x-frame-options'),
    'x-xss-protection': checkHeader(headers, 'x-xss-protection'),
    'referrer-policy': checkHeader(headers, 'referrer-policy'),
    'permissions-policy': checkHeader(headers, 'permissions-policy'),
    'cross-origin-embedder-policy': checkHeader(headers, 'cross-origin-embedder-policy'),
    'cross-origin-opener-policy': checkHeader(headers, 'cross-origin-opener-policy'),
    'cross-origin-resource-policy': checkHeader(headers, 'cross-origin-resource-policy')
  };
  
  // Calculate security score
  const securityScore = calculateSecurityScore(securityHeaders);
  
  // Generate recommendations
  const recommendations = generateRecommendations(securityHeaders);
  
  return {
    securityHeaders,
    securityScore,
    recommendations
  };
}

/**
 * Check if a header exists
 * @param {Object} headers - The normalized headers
 * @param {string} headerName - The header name to check
 * @returns {Object|null} - Header information or null if not found
 */
function checkHeader(headers, headerName) {
  // Try exact match first
  if (headers[headerName]) {
    return {
      present: true,
      value: headers[headerName]
    };
  }
  
  // Try case-insensitive match
  const headerNameLower = headerName.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === headerNameLower) {
      return {
        present: true,
        value: headers[key]
      };
    }
  }
  
  // Check for alternative header names
  const alternativeNames = {
    'x-content-type-options': ['x-content-options'],
    'permissions-policy': ['feature-policy'],
    'content-security-policy': ['content-security-policy-report-only']
  };
  
  if (alternativeNames[headerNameLower]) {
    for (const altName of alternativeNames[headerNameLower]) {
      for (const key of Object.keys(headers)) {
        if (key.toLowerCase() === altName.toLowerCase()) {
          return {
            present: true,
            value: headers[key]
          };
        }
      }
    }
  }
  
  return {
    present: false,
    value: null
  };
}

/**
 * Calculate security score based on headers
 * @param {Object} securityHeaders - The security headers
 * @returns {Object} - Security score information
 */
function calculateSecurityScore(securityHeaders) {
  // Define weights for each security header
  const weights = {
    'strict-transport-security': 15,
    'content-security-policy': 20,
    'x-content-type-options': 10,
    'x-frame-options': 10,
    'x-xss-protection': 5,
    'referrer-policy': 5,
    'permissions-policy': 10,
    'cross-origin-embedder-policy': 5,
    'cross-origin-opener-policy': 5,
    'cross-origin-resource-policy': 5
  };
  
  // Calculate score
  let score = 0;
  let maxScore = 0;
  
  Object.keys(securityHeaders).forEach(header => {
    const weight = weights[header] || 0;
    maxScore += weight;
    
    if (securityHeaders[header].present) {
      score += weight;
    }
  });
  
  // Convert to percentage
  const percentage = Math.round((score / maxScore) * 100);
  
  // Determine rating
  let rating;
  if (percentage >= 90) {
    rating = 'A+';
  } else if (percentage >= 80) {
    rating = 'A';
  } else if (percentage >= 70) {
    rating = 'B';
  } else if (percentage >= 60) {
    rating = 'C';
  } else if (percentage >= 50) {
    rating = 'D';
  } else {
    rating = 'F';
  }
  
  return {
    score,
    maxScore,
    percentage,
    rating
  };
}

/**
 * Generate recommendations based on missing headers
 * @param {Object} securityHeaders - The security headers
 * @returns {Array} - List of recommendations
 */
function generateRecommendations(securityHeaders) {
  const recommendations = [];
  
  // Check for missing headers and provide recommendations
  if (!securityHeaders['strict-transport-security'].present) {
    recommendations.push({
      header: 'Strict-Transport-Security',
      recommendation: 'Add the HSTS header to ensure secure connections',
      example: 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'
    });
  }
  
  if (!securityHeaders['content-security-policy'].present) {
    recommendations.push({
      header: 'Content-Security-Policy',
      recommendation: 'Add a Content Security Policy to prevent XSS attacks',
      example: "Content-Security-Policy: default-src 'self'; script-src 'self'"
    });
  }
  
  if (!securityHeaders['x-content-type-options'].present) {
    recommendations.push({
      header: 'X-Content-Type-Options',
      recommendation: 'Add X-Content-Type-Options to prevent MIME type sniffing',
      example: 'X-Content-Type-Options: nosniff'
    });
  }
  
  if (!securityHeaders['x-frame-options'].present) {
    recommendations.push({
      header: 'X-Frame-Options',
      recommendation: 'Add X-Frame-Options to prevent clickjacking',
      example: 'X-Frame-Options: DENY'
    });
  }
  
  if (!securityHeaders['referrer-policy'].present) {
    recommendations.push({
      header: 'Referrer-Policy',
      recommendation: 'Add Referrer-Policy to control referrer information',
      example: 'Referrer-Policy: strict-origin-when-cross-origin'
    });
  }
  
  return recommendations;
}

/**
 * Check for HTTP to HTTPS redirects
 * @param {string} domain - The domain to check
 * @returns {Promise<Object>} - Redirect information
 */
async function checkRedirects(domain) {
  try {
    // Check HTTP redirect
    const redirectInfo = await checkHttpRedirect(domain);
    
    return {
      hasHttpsRedirect: redirectInfo.redirectsToHttps,
      redirectChain: redirectInfo.redirectChain,
      finalUrl: redirectInfo.finalUrl
    };
  } catch (error) {
    return {
      hasHttpsRedirect: false,
      redirectChain: [],
      finalUrl: null,
      error: error.message
    };
  }
}

/**
 * Check if HTTP redirects to HTTPS
 * @param {string} domain - The domain to check
 * @returns {Promise<Object>} - Redirect information
 */
function checkHttpRedirect(domain) {
  return new Promise((resolve) => {
    const options = {
      host: domain,
      port: 80,
      method: 'HEAD',
      path: '/',
      timeout: 10000,
      followRedirect: false
    };
    
    const redirectChain = [];
    let finalUrl = `http://${domain}`;
    let redirectsToHttps = false;
    
    function followRedirect(url, depth = 0) {
      if (depth > 5) {
        // Prevent infinite redirect loops
        resolve({
          redirectsToHttps,
          redirectChain,
          finalUrl
        });
        return;
      }
      
      try {
        const parsedUrl = new URL(url);
        const isHttps = parsedUrl.protocol === 'https:';
        
        if (isHttps) {
          redirectsToHttps = true;
        }
        
        const protocol = isHttps ? https : http;
        const port = isHttps ? 443 : 80;
        
        const reqOptions = {
          host: parsedUrl.hostname,
          port: parsedUrl.port || port,
          method: 'HEAD',
          path: parsedUrl.pathname + parsedUrl.search,
          timeout: 10000,
          rejectUnauthorized: false
        };
        
        const req = protocol.request(reqOptions, (res) => {
          redirectChain.push({
            url,
            statusCode: res.statusCode
          });
          
          if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
            // Handle relative URLs
            let redirectUrl = res.headers.location;
            if (redirectUrl.startsWith('/')) {
              redirectUrl = `${parsedUrl.protocol}//${parsedUrl.host}${redirectUrl}`;
            }
            
            finalUrl = redirectUrl;
            followRedirect(redirectUrl, depth + 1);
          } else {
            finalUrl = url;
            resolve({
              redirectsToHttps,
              redirectChain,
              finalUrl
            });
          }
        });
        
        req.on('error', () => {
          resolve({
            redirectsToHttps,
            redirectChain,
            finalUrl
          });
        });
        
        req.on('timeout', () => {
          req.destroy();
          resolve({
            redirectsToHttps,
            redirectChain,
            finalUrl
          });
        });
        
        req.end();
      } catch (error) {
        resolve({
          redirectsToHttps,
          redirectChain,
          finalUrl
        });
      }
    }
    
    followRedirect(`http://${domain}`);
  });
}

module.exports = { analyzeHeaders }; 