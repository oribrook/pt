/**
 * Filters and normalizes endpoints from trackAjaxCalls results to focus on security-relevant endpoints
 * @param {Object} trackingResults - Results object from trackAjaxCalls function
 * @param {Object} options - Configuration options
 * @param {string[]} options.ignoredExtensions - File extensions to ignore
 * @param {string[]} options.ignoredPatterns - URL patterns to ignore
 * @param {boolean} options.ignoreQueryParams - Whether to remove query parameters from URLs
 * @param {boolean} options.ignoreExternalDomains - Whether to ignore external domains
 * @returns {string[]} - Array of unique, relevant endpoint URLs
 */
export function filterSecurityEndpoints(trackingResults, options = {}) {
    // Default options
    const config = {
        ignoredExtensions: ['.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.eot', '.ico'],
        ignoredPatterns: ['bootstrap', 'jquery', 'analytics', 'tracking', 'gtm', 'cdn', 'fonts', 'static', 'assets'],
        ignoreQueryParams: true,
        ignoreExternalDomains: true,
        ...options
    };

    const baseUrl = new URL(trackingResults.endpoints[0]?.url || '');
    const baseDomain = baseUrl.hostname;
    const uniqueUrls = new Set();

    // Helper function to normalize URLs
    function normalizeUrl(urlString) {
        try {
            const url = new URL(urlString);
            
            // Remove query parameters if configured
            if (config.ignoreQueryParams) {
                return `${url.origin}${url.pathname}`;
            }
            
            return url.href;
        } catch (error) {
            return urlString; // Return original if parsing fails
        }
    }

    // Process each endpoint
    trackingResults.endpoints.forEach(endpoint => {
        try {
            // Skip empty or null URLs
            if (!endpoint.url) return;
            
            const url = new URL(endpoint.url);
            
            // Skip external domains if configured
            if (config.ignoreExternalDomains && url.hostname !== baseDomain) return;
            
            // Skip ignored file extensions
            const extension = url.pathname.split('.').pop().toLowerCase();
            if (config.ignoredExtensions.includes(`.${extension}`)) return;
            
            // Skip ignored patterns
            if (config.ignoredPatterns.some(pattern => 
                url.href.toLowerCase().includes(pattern.toLowerCase()))) return;
            
            // Skip non-API requests (typically static resources)
            if (endpoint.type === 'stylesheet' || 
                endpoint.type === 'image' || 
                endpoint.type === 'font' || 
                endpoint.type === 'media') return;
            
            // Add normalized URL to results
            uniqueUrls.add(normalizeUrl(endpoint.url));
            
        } catch (error) {
            console.error(`Error processing endpoint: ${endpoint.url}`, error);
        }
    });

    // Convert Set to Array and return
    return Array.from(uniqueUrls);
}

/**
 * Analyzes the filtered endpoints and categorizes them based on potential security risks
 * @param {string[]} endpoints - Array of endpoint URLs
 * @returns {Object} - Object containing categorized endpoints
 */
export function categorizeEndpoints(endpoints) {
    const categories = {
        authentication: [],
        dataAccess: [],
        fileOperations: [],
        userManagement: [],
        configurationEndpoints: [],
        other: []
    };

    // Keywords for each category
    const patterns = {
        authentication: ['login', 'auth', 'token', 'session', 'password', 'signin', 'signup', 'register', 'oauth'],
        dataAccess: ['api', 'data', 'query', 'search', 'find', 'get', 'list', 'fetch'],
        fileOperations: ['upload', 'download', 'file', 'document', 'image', 'media', 'import', 'export'],
        userManagement: ['user', 'account', 'profile', 'admin', 'role', 'permission', 'group'],
        configurationEndpoints: ['config', 'setting', 'option', 'preference', 'admin', 'dashboard']
    };

    endpoints.forEach(endpoint => {
        const lowerEndpoint = endpoint.toLowerCase();
        let categorized = false;
        
        // Check each category
        for (const [category, keywords] of Object.entries(patterns)) {
            if (keywords.some(keyword => lowerEndpoint.includes(keyword))) {
                categories[category].push(endpoint);
                categorized = true;
                break; // Assign to only one category
            }
        }
        
        // If not categorized, add to "other"
        if (!categorized) {
            categories.other.push(endpoint);
        }
    });

    return categories;
}

/**
 * Processes the results from trackAjaxCalls and returns a simplified array of unique security-relevant endpoints
 * @param {Object} trackingResults - Results from trackAjaxCalls
 * @param {boolean} [categorize=false] - Whether to categorize endpoints
 * @returns {string[]|Object} - Array of unique URLs or categorized object
 */
export function processSecurityEndpoints(trackingResults, categorize = false) {
    // Filter endpoints
    const filteredEndpoints = filterSecurityEndpoints(trackingResults);
    
    // Return categorized endpoints if requested
    if (categorize) {
        return categorizeEndpoints(filteredEndpoints);
    }
    
    return filteredEndpoints;
}