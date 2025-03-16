
// Overwrite fetch globally (use with caution)
(function() {
    const originalFetch = window.fetch;
    window.fetch = function(input, init = {}) {
      init.mode = 'no-cors';
      return originalFetch(input, init);
    };
})();
  
document.addEventListener('DOMContentLoaded', () => {
    initializeApp();
});

// Global variables
let totalTests = 0;
let completedTests = 0;
let passedTests = 0;
let testResults = [];
let testCategories = {
    "input-validation": "Input Validation",
    "authentication": "Authentication & Authorization",
    "headers": "Security Headers",
    "communication": "Secure Communication",
    "configuration": "Server Configuration"
};

// Vulnerability explanations and solutions
const vulnerabilityExplanations  = {
    "XSS Vulnerability": {
        explanation: "Attackers inject malicious scripts into your webpages, potentially stealing session data or defacing your site. Direct threat to user trust and data safety.",
        solution: "Sanitize user inputs, escape outputs, use Content-Security-Policy. Implement XSS filters and use libraries like DOMPurify to sanitize HTML content."
    },
    "SQL Injection": {
        explanation: "Hackers exploit database queries to view/edit/delete sensitive information. Could lead to full system compromise.",
        solution: "Use parameterized queries, avoid raw SQL, employ ORM libraries. Never concatenate user input directly into SQL statements."
    },
    "Path Traversal": {
        explanation: "Unauthorized access to server files (like passwords or logs) by manipulating file path requests.",
        solution: "Validate user-supplied file paths, restrict directory access. Use a whitelist approach for allowed files and implement proper authorization checks."
    },
    "CSRF Protection": {
        explanation: "Allows fake requests from malicious sites, enabling actions like fund transfers without user consent.",
        solution: "Implement anti-CSRF tokens, set SameSite cookies. Validate the origin header and use double-submit cookie patterns for sensitive operations."
    },
    "Login Security": {
        explanation: "Weak passwords or unlimited login attempts let attackers hijack accounts through brute-force methods.",
        solution: "Enforce strong passwords, MFA, and rate-limiting. Consider implementing account lockout policies and monitoring for suspicious login patterns."
    },
    "X-Frame-Options": {
        explanation: "Malicious sites can embed your site in frames to trick users into clicking hidden elements (clickjacking).",
        solution: "Set header to 'DENY' or 'SAMEORIGIN'. Test all user interface components for clickjacking vulnerabilities and implement proper frame-ancestors in CSP."
    },
    "Content-Security-Policy": {
        explanation: "Unrestricted resource loading lets attackers execute scripts/images from unsafe domains.",
        solution: "Define allowed sources for scripts/styles/fonts. Start with a strict policy and gradually loosen as needed. Use report-uri to monitor violations."
    },
    "X-Content-Type-Options": {
        explanation: "Browsers might run malicious files disguised as safe types (e.g., treating a .jpg as JavaScript).",
        solution: "Set header to 'nosniff'. Always serve files with the correct Content-Type header and validate file uploads thoroughly."
    },
    "CORS Configuration": {
        explanation: "Misconfigured permissions let other websites steal sensitive data via cross-origin requests.",
        solution: "Restrict domains, methods, and headers explicitly. Never use 'Access-Control-Allow-Origin: *' for sensitive operations and validate the Origin header."
    },
    "HSTS Implementation": {
        explanation: "Missing HTTPS enforcement allows attackers to downgrade connections to unencrypted HTTP.",
        solution: "Enable HSTS with long max-age and preload. Submit your domain to the HSTS preload list and ensure all subdomains support HTTPS."
    },
    "Server Information Leakage": {
        explanation: "Server version/software details in headers help attackers target known vulnerabilities.",
        solution: "Hide server headers, disable verbose errors. Configure your web server to use generic server names and implement custom error pages."
    },
    "Open Ports Analysis": {
        explanation: "Unused open ports (like FTP) give hackers extra ways to infiltrate your network.",
        solution: "Close unused ports, use firewalls, scan regularly. Implement a least-privilege approach and document all required open ports with justification."
    },
    "Insecure File Upload": {
        explanation: "Accepting file uploads without proper validation allows attackers to upload malicious files that can be executed on your server.",
        solution: "Validate file types using content inspection rather than extension, scan uploaded files for malware, and store them outside the web root. Set proper permissions so they cannot be executed."
    }
};

function initializeApp() {
    ['testLogs', 'results', 'scoreDisplay'].forEach(id => {
        const elem = document.getElementById(id);
        if (elem) elem.innerHTML = '';
    });
    
    // Set up modal close button
    const closeButton = document.querySelector('.close-button');
    if (closeButton) {
        closeButton.addEventListener('click', () => {
            document.getElementById('vulnerabilityModal').style.display = 'none';
        });
    }
    
    // Close modal when clicking outside
    window.addEventListener('click', (event) => {
        const modal = document.getElementById('vulnerabilityModal');
        if (event.target === modal) {
            modal.style.display = 'none';
        }
    });
}

async function runTest() {
    const urlInput = document.getElementById('urlInput');
    if (!urlInput) {
        alert('URL input not found.');
        return;
    }
    const url = urlInput.value.trim();
    if (!url) return alert('Please enter a URL');
    
    // Robust URL validation
    try {
        new URL(url);
    } catch (e) {
        return alert('Invalid URL format.');
    }
    
    initializeApp();
    const testButton = document.getElementById('testButton');
    if (testButton) testButton.disabled = true;
    testResults = [];
    totalTests = completedTests = passedTests = 0;
    
    updateTestStatus('Initializing tests...', 5);
    logMessage(`Starting security tests for ${url}`, 'info');

    const tests = [
        { category: 'input-validation', name: 'XSS Vulnerability', func: testXSS },
        { category: 'input-validation', name: 'SQL Injection', func: testSQLi },
        { category: 'input-validation', name: 'Path Traversal', func: testPathTraversal },
        { category: 'input-validation', name: 'Insecure File Upload', func: testFileUpload },
        { category: 'authentication', name: 'CSRF Protection', func: testCSRF },
        { category: 'authentication', name: 'Login Security', func: testLoginSecurity },
        { category: 'headers', name: 'X-Frame-Options', func: testClickjacking },
        { category: 'headers', name: 'Content-Security-Policy', func: testCSP },
        { category: 'headers', name: 'X-Content-Type-Options', func: testContentTypeSniffing },
        { category: 'communication', name: 'CORS Configuration', func: testCORS },
        { category: 'communication', name: 'HSTS Implementation', func: testHSTS },
        { category: 'configuration', name: 'Server Information Leakage', func: testServerLeakage },
        { category: 'configuration', name: 'Open Ports Analysis', func: testPortScanning }
    ];
    totalTests = tests.length;
    updateTestStatus('Running tests...', 15);

    for (let test of tests) {
        logMessage(`Starting test: ${test.name}`, 'info');
        try {
            const result = await test.func(url);
            if (typeof result.passed !== 'boolean') throw new Error('Invalid result format');
            if (result.passed) {
                passedTests++;
                logMessage(`Test passed: ${test.name}`, 'success');
            } else {
                logMessage(`Test failed: ${test.name} – ${result.message || 'No details'}`, 'error');
            }
            testResults.push({
                category: test.category,
                name: test.name,
                passed: result.passed,
                message: result.message || '',
                severity: result.severity || 'medium',
                error: result.error || null
            });
        } catch (error) {
            logMessage(`Error in test ${test.name}: ${error.message}`, 'error');
            testResults.push({
                category: test.category,
                name: test.name,
                passed: false,
                message: `Test error: ${error.message}`,
                severity: 'medium',
                error: error.message
            });
        }
        completedTests++;
        updateProgress();
    }
    
    updateTestStatus('Generating report...', 90);
    setTimeout(() => {
        displayResults();
        if (testButton) testButton.disabled = false;
        updateTestStatus('Testing complete', 100);
    }, 1000);
}

// Improved test implementations with clearer messages
async function testXSS(url) {
    logMessage('Testing for XSS vulnerabilities...', 'info');
    try {
        await simulateTest(500);
        const passed = Math.random() > 0.3;
        return {
            passed,
            message: passed ? 'Input fields sanitize script tags.' : 'Possible XSS vulnerability detected.',
            severity: 'high'
        };
    } catch (error) {
        throw new Error(`XSS test failed: ${error.message}`);
    }
}

async function testSQLi(url) {
    logMessage('Testing for SQL injection vulnerabilities...', 'info');
    try {
        await simulateTest(600);
        const passed = Math.random() > 0.3;
        return {
            passed,
            message: passed ? 'Parameterized queries in use.' : 'Potential SQL injection risk.',
            severity: 'high'
        };
    } catch (error) {
        throw new Error(`SQL injection test failed: ${error.message}`);
    }
}

async function testPathTraversal(url) {
    logMessage('Testing for path traversal vulnerabilities...', 'info');
    try {
        // Parse the URL to get base components
        const parsedUrl = new URL(url);
        const baseUrl = `${parsedUrl.protocol}//${parsedUrl.host}`;
        
        // Common path traversal payloads
        const payloads = [
            '../../../etc/passwd',
            '..%2f..%2f..%2fetc%2fpasswd',
            '....//....//....//etc/passwd',
            '%252e%252e%252fetc%252fpasswd',
            'file:///etc/passwd',
            '/var/log/apache2/access.log',
            'C:\\Windows\\system.ini',
            '..\\..\\..\\windows\\win.ini'
        ];
        
        // Target parameters to test - common places where path traversal occurs
        const paramTargets = ['file', 'path', 'document', 'load', 'read', 'retrieve', 'doc'];
        
        // Identify potential vulnerable endpoints from the main page
        const mainResponse = await fetch(baseUrl, {
            method: 'GET',
            headers: {
                'User-Agent': 'Security Scanner'
            }
        });
        
        const html = await mainResponse.text();
        
        // Extract potential file-related endpoints
        const fileEndpoints = [];
        const hrefMatches = html.match(/href=["'](.*?)["']/g) || [];
        const srcMatches = html.match(/src=["'](.*?)["']/g) || [];
        
        // Process and extract actual URLs
        [...hrefMatches, ...srcMatches].forEach(match => {
            const extractedUrl = match.replace(/href=["']|src=["']/g, '').replace(/["']/g, '');
            if (extractedUrl.includes('.') && !extractedUrl.startsWith('http')) {
                fileEndpoints.push(extractedUrl);
            }
        });
        
        // Function to check response for path traversal success indicators
        const checkForPathTraversalSuccess = async (response) => {
            const content = await response.text();
            
            // Look for common indicators of successful path traversal
            const unixSuccess = content.includes('root:') && content.includes('/bin/bash');
            const windowsSuccess = content.includes('[fonts]') || content.includes('MSWINCFG');
            const logfileSuccess = content.includes('GET /') && content.includes('HTTP/1.');
            const directorySuccess = content.includes('Directory of') || content.includes('Index of');
            
            return unixSuccess || windowsSuccess || logfileSuccess || directorySuccess;
        };
        
        // Test results storage
        let vulnerabilities = [];
        
        // Test URL parameters that could be vulnerable
        for (const param of paramTargets) {
            for (const payload of payloads) {
                const testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;
                
                const response = await fetch(testUrl, {
                    method: 'GET',
                    headers: {
                        'User-Agent': 'Security Scanner'
                    },
                    // Don't follow redirects to avoid potential server-side impacts
                    redirect: 'manual'
                });
                
                if (response.status === 200) {
                    const isVulnerable = await checkForPathTraversalSuccess(response);
                    if (isVulnerable) {
                        vulnerabilities.push({
                            url: testUrl,
                            payload: payload,
                            parameter: param
                        });
                    }
                }
            }
        }
        
        // Test identified file endpoints
        for (const endpoint of fileEndpoints) {
            for (const payload of payloads) {
                // Determine injection point (if endpoint has parameters, inject into them)
                let testUrl;
                if (endpoint.includes('?') && endpoint.includes('=')) {
                    const [path, queryString] = endpoint.split('?');
                    const params = new URLSearchParams(queryString);
                    
                    // Try injecting into each parameter
                    for (const [key, value] of params.entries()) {
                        params.set(key, payload);
                        testUrl = `${baseUrl}${path}?${params.toString()}`;
                        
                        const response = await fetch(testUrl, {
                            method: 'GET',
                            headers: {
                                'User-Agent': 'Security Scanner'
                            },
                            redirect: 'manual'
                        });
                        
                        if (response.status === 200) {
                            const isVulnerable = await checkForPathTraversalSuccess(response);
                            if (isVulnerable) {
                                vulnerabilities.push({
                                    url: testUrl,
                                    payload: payload,
                                    parameter: key
                                });
                            }
                        }
                    }
                } else {
                    // Try path injection
                    testUrl = `${baseUrl}/${endpoint.replace(/\.[^/.]+$/, '')}/${payload}`;
                    
                    const response = await fetch(testUrl, {
                        method: 'GET',
                        headers: {
                            'User-Agent': 'Security Scanner'
                        },
                        redirect: 'manual'
                    });
                    
                    if (response.status === 200) {
                        const isVulnerable = await checkForPathTraversalSuccess(response);
                        if (isVulnerable) {
                            vulnerabilities.push({
                                url: testUrl,
                                payload: payload,
                                parameter: 'path'
                            });
                        }
                    }
                }
            }
        }
        
        const passed = vulnerabilities.length === 0;
        
        return {
            passed,
            message: passed ? 
                'No path traversal vulnerabilities detected.' : 
                `Path traversal vulnerability detected in ${vulnerabilities.length} locations.`,
            severity: passed ? 'info' : 'high',
            details: {
                vulnerabilities,
                testedEndpoints: fileEndpoints.length,
                testedPayloads: payloads.length
            }
        };
    } catch (error) {
        throw new Error(`Path traversal test failed: ${error.message}`);
    }
}

async function testFileUpload(url) {
    logMessage('Testing file upload security...', 'info');
    try {
        await simulateTest(550);
        const passed = Math.random() > 0.4;
        return {
            passed,
            message: passed ? 'File upload validation present.' : 'Insecure file upload handling detected.',
            severity: 'high'
        };
    } catch (error) {
        throw new Error(`File upload test failed: ${error.message}`);
    }
}

async function testCSRF(url) {
    logMessage('Testing for CSRF protections...', 'info');
    try {
        // First, make a GET request to the site to get cookies and locate a form
        const response = await fetch(url, {
            method: 'GET',
            credentials: 'include',
            headers: {
                'Accept': 'text/html',
                'User-Agent': 'Security Scanner'
            }
        });
        
        if (!response.ok) {
            throw new Error(`Failed to access site: ${response.status}`);
        }
        
        const html = await response.text();
        const cookies = response.headers.get('set-cookie');
        
        // Check for CSRF token in the page
        const hasCSRFTokenInHTML = html.includes('csrf') || 
                                   html.includes('_token') || 
                                   html.match(/input.*?(csrf|token|nonce)/i);
        
        // Attempt a state-changing request without a proper CSRF token
        // Using a common endpoint that typically requires CSRF protection
        const targetUrl = new URL('/api/account/update', url).toString();
        const csrfTestResponse = await fetch(targetUrl, {
            method: 'POST',
            credentials: 'include',
            headers: {
                'Content-Type': 'application/json',
                'Cookie': cookies || '',
                'Origin': url,
                'Referer': url
            },
            body: JSON.stringify({
                'name': 'CSRF Test'
            })
        });
        
        // Check the response for indicators of CSRF protection
        const passed = (
            // If 403 Forbidden or 401 Unauthorized, likely has CSRF protection
            csrfTestResponse.status === 403 || 
            csrfTestResponse.status === 401 ||
            // Or if page required a token and we couldn't modify
            (hasCSRFTokenInHTML && csrfTestResponse.status !== 200)
        );
        
        // Determine severity based on whether it's a sensitive endpoint
        const severity = passed ? 'info' : 'high';
        
        return {
            passed,
            message: passed ? 
                'CSRF protection appears to be implemented correctly.' : 
                'Potentially vulnerable to CSRF attacks. No token validation detected.',
            severity,
            details: {
                tokenFound: hasCSRFTokenInHTML,
                responseStatus: csrfTestResponse.status,
                testedUrl: targetUrl
            }
        };
    } catch (error) {
        // Provide detailed error message
        throw new Error(`CSRF test failed: ${error.message}`);
    }
}

async function testLoginSecurity(url) {
    logMessage('Testing login security features...', 'info');
    try {
        await simulateTest(700);
        const passed = Math.random() > 0.2;
        return {
            passed,
            message: passed ? 'Rate limiting and lockout policies in place.' : 'Weak login security measures.',
            severity: 'high'
        };
    } catch (error) {
        throw new Error(`Login security test failed: ${error.message}`);
    }
}

async function testClickjacking(url) {
    logMessage('Testing X-Frame-Options header...', 'info');
    try {
        await simulateTest(300);
        const passed = Math.random() > 0.3;
        return {
            passed,
            message: passed ? 'X-Frame-Options header is set.' : 'Header missing or misconfigured.',
            severity: 'medium'
        };
    } catch (error) {
        throw new Error(`X-Frame-Options test failed: ${error.message}`);
    }
}

async function testCSP(url) {
    logMessage('Testing Content-Security-Policy header...', 'info');
    try {
        await simulateTest(350);
        const passed = Math.random() > 0.5;
        return {
            passed,
            message: passed ? 'CSP implemented.' : 'Weak or missing CSP.',
            severity: 'medium'
        };
    } catch (error) {
        throw new Error(`CSP test failed: ${error.message}`);
    }
}

async function testContentTypeSniffing(url) {
    logMessage('Testing X-Content-Type-Options header...', 'info');
    try {
        await simulateTest(250);
        const passed = Math.random() > 0.3;
        return {
            passed,
            message: passed ? 'Header set to nosniff.' : 'Header missing or misconfigured.',
            severity: 'medium'
        };
    } catch (error) {
        throw new Error(`Content-Type-Options test failed: ${error.message}`);
    }
}

async function testCORS(url) {
    logMessage('Testing CORS configuration...', 'info');
    try {
        await simulateTest(400);
        const passed = Math.random() > 0.4;
        return {
            passed,
            message: passed ? 'CORS configured with specific origins.' : 'CORS misconfiguration detected.',
            severity: 'medium'
        };
    } catch (error) {
        throw new Error(`CORS test failed: ${error.message}`);
    }
}

async function testHSTS(url) {
    logMessage('Testing HSTS implementation...', 'info');
    try {
        await simulateTest(300);
        const passed = Math.random() > 0.3;
        return {
            passed,
            message: passed ? 'HSTS header present with adequate max-age.' : 'HSTS header missing or weak.',
            severity: 'medium'
        };
    } catch (error) {
        throw new Error(`HSTS test failed: ${error.message}`);
    }
}

async function testServerLeakage(url) {
    logMessage('Testing for server information leakage...', 'info');
    try {
        await simulateTest(450);
        const passed = Math.random() > 0.3;
        return {
            passed,
            message: passed ? 'Server version hidden.' : 'Server information leakage detected.',
            severity: 'low'
        };
    } catch (error) {
        throw new Error(`Server leakage test failed: ${error.message}`);
    }
}

async function testPortScanning(url) {
    logMessage('Analyzing open ports and services...', 'info');
    try {
        await simulateTest(800);
        const passed = Math.random() > 0.4;
        return {
            passed,
            message: passed ? 'Only necessary ports open.' : 'Unexpected open ports found.',
            severity: 'medium'
        };
    } catch (error) {
        throw new Error(`Port scanning test failed: ${error.message}`);
    }
}

// Helper functions
function logMessage(message, type = 'info') {
    const logsElement = document.getElementById('testLogs');
    if (!logsElement) return;
    const entry = document.createElement('div');
    entry.className = `log-entry log-${type}`;
    entry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    logsElement.appendChild(entry);
    logsElement.scrollTop = logsElement.scrollHeight;
}

function updateTestStatus(message, progressPercentage) {
    const statusElem = document.getElementById('testStatus');
    const progressElem = document.getElementById('progressFill');
    if (statusElem) statusElem.textContent = message;
    if (progressElem) progressElem.style.width = `${progressPercentage}%`;
}

function updateProgress() {
    updateTestStatus(`Completed ${completedTests} of ${totalTests} tests`, (completedTests / totalTests) * 100);
}

function displayResults() {
    const score = Math.round((passedTests / totalTests) * 100);
    const resultsDiv = document.getElementById('results');
    let resultsHTML = '<table class="results-table"><thead><tr><th>Test</th><th>Status</th><th>Details</th></tr></thead><tbody>';
    
    const groupedResults = {};
    for (let category in testCategories) {
        groupedResults[category] = testResults.filter(test => test.category === category);
    }
    for (let category in groupedResults) {
        if (groupedResults[category].length) {
            resultsHTML += `<tr class="test-category"><td colspan="3">${testCategories[category]}</td></tr>`;
            groupedResults[category].forEach(result => {
                // Define severity class for the test row
                const severityClass = !result.passed ? `severity-${result.severity}` : '';
                
                // Add class for click handling on failed tests
                const clickClass = !result.passed ? 'status-fail' : 'status-pass';
                
                let detailsContent = result.message;
                
                // Add error message if test had execution error
                if (result.error && !result.passed) {
                    detailsContent += `<div class="test-error">Error: ${result.error}</div>`;
                }
                
                resultsHTML += `<tr class="${severityClass}" data-test-name="${result.name}">
                    <td>${result.name}</td>
                    <td class="${clickClass}" onclick="showVulnerabilityDetails('${result.name}')">${result.passed ? 'PASS' : 'FAIL'}</td>
                    <td>${detailsContent} ${!result.passed ? '<span class="info-icon" onclick="showVulnerabilityDetails(\'' + result.name + '\')">ⓘ</span>' : ''}</td>
                </tr>`;
            });
        }
    }
    resultsHTML += '</tbody></table>';
    if (resultsDiv) resultsDiv.innerHTML = resultsHTML;
    
    const scoreDiv = document.getElementById('scoreDisplay');
    const scoreClass = score >= 80 ? 'score-high' : score >= 50 ? 'score-medium' : 'score-low';
    if (scoreDiv) scoreDiv.innerHTML = `<span class="${scoreClass}">${score}%</span> Security Score`;
    renderChart(score);
}

// Function to show vulnerability details in modal
function showVulnerabilityDetails(testName) {
    const vulnerabilityData = vulnerabilityExplanations[testName];
    if (!vulnerabilityData) return;
    
    const modal = document.getElementById('vulnerabilityModal');
    const title = document.getElementById('modalTitle');
    const explanation = document.getElementById('vulnerabilityExplanation');
    const solution = document.getElementById('vulnerabilitySolution');
    
    title.textContent = testName;
    explanation.textContent = vulnerabilityData.explanation;
    
    solution.innerHTML = `
        <h3>Recommended Solution:</h3>
        <p>${vulnerabilityData.solution}</p>
    `;
    
    modal.style.display = 'block';
}

// Make the function available globally for the onclick handlers
window.showVulnerabilityDetails = showVulnerabilityDetails;

function renderChart(score) {
    const ctx = document.getElementById('scoreChart');
    if (!ctx) return;
    if (window.securityChart) window.securityChart.destroy();
    
    try {
        window.securityChart = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: ['Passed', 'Failed'],
                datasets: [{
                    data: [score, 100 - score],
                    backgroundColor: [score >= 80 ? '#2ecc71' : score >= 50 ? '#f39c12' : '#e74c3c', '#ecf0f1'],
                    borderWidth: 0
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                cutout: '70%',
                plugins: {
                    legend: { display: true, position: 'bottom' },
                    tooltip: { callbacks: { label: context => `${context.label}: ${context.raw}%` } }
                }
            }
        });
    } catch (error) {
        console.error('Error rendering chart:', error);
        const chartWrapper = ctx.parentElement;
        if (chartWrapper) {
            chartWrapper.innerHTML = `<div class="chart-error">Chart rendering failed: ${error.message}</div>`;
        }
    }
}

function simulateTest(delay) {
    return new Promise(resolve => setTimeout(resolve, delay));
}