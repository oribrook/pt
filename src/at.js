import axios from 'axios';

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function testOpenRedirect(url) {
    const results = { warnings: [], notes: [] };

    try {
        const testUrl = `${url}?redirect=https://evil.com`;
        const response = await axios.get(testUrl, { maxRedirects: 0 });

        if (response.headers.location && response.headers.location.includes('evil.com')) {
            results.warnings.push('Potential open redirect vulnerability');
            results.notes.push(`Redirect header points to: ${response.headers.location}`);
        } else {
            results.notes.push('No open redirect detected');
        }
    } catch (error) {
        if (error.response?.status >= 300 && error.response?.status < 400) {
            results.warnings.push('Potential open redirect found');
            results.notes.push(`Redirect detected to: ${error.response.headers.location}`);
        } else {
            results.notes.push('No open redirect behavior detected');
        }
    }

    return {
        passed: results.warnings.length === 0,
        ...results,
        notes: results.notes.join(', ')
    };
}

async function testSecurityHeaders(url) {
    const results = { warnings: [], notes: [] };

    try {
        const response = await axios.get(url);
        const headers = response.headers;

        const requiredHeaders = {
            'strict-transport-security': 'HSTS missing',
            'x-content-type-options': 'X-Content-Type-Options missing',
            'referrer-policy': 'Referrer-Policy missing',
            'x-xss-protection': 'X-XSS-Protection missing or weak'
        };

        for (const [header, warning] of Object.entries(requiredHeaders)) {
            if (!headers[header]) {
                results.warnings.push(warning);
            } else {
                results.notes.push(`${header}: ${headers[header]}`);
            }
        }
    } catch (error) {
        results.notes.push(`Failed to fetch headers: ${error.message}`);
    }

    return {
        passed: results.warnings.length === 0,
        ...results,
        notes: results.notes.join(', ')
    };
}

async function testSSRF(url) {
    const results = { warnings: [], notes: [] };

    try {
        const payload = `${url}?url=http://169.254.169.254/latest/meta-data/`;
        const response = await axios.get(payload, { timeout: 3000 });

        if (response.status === 200) {
            results.warnings.push('Potential SSRF vulnerability');
            results.notes.push('Server responded to internal AWS metadata request');
        } else {
            results.notes.push('No SSRF behavior detected');
        }
    } catch (error) {
        if (error.code === 'ECONNABORTED') {
            results.notes.push('SSRF request timed out (likely safe)');
        } else {
            results.notes.push('Server rejected internal request (likely safe)');
        }
    }

    return {
        passed: results.warnings.length === 0,
        ...results,
        notes: results.notes.join(', ')
    };
}

async function testInsecureCookies(url) {
    const results = { warnings: [], notes: [] };

    try {
        const response = await axios.get(url);
        const cookies = response.headers['set-cookie'] || [];

        if (cookies.length === 0) {
            results.notes.push('No cookies set by the server');
        }

        for (const cookie of cookies) {
            if (!cookie.includes('HttpOnly')) {
                results.warnings.push('Cookie missing HttpOnly flag');
            }
            if (!cookie.includes('Secure')) {
                results.warnings.push('Cookie missing Secure flag');
            }
            if (!cookie.includes('SameSite')) {
                results.warnings.push('Cookie missing SameSite attribute');
            }
        }
    } catch (error) {
        results.notes.push(`Failed to fetch cookies: ${error.message}`);
    }

    return {
        passed: results.warnings.length === 0,
        ...results,
        notes: results.notes.join(', ')
    };
}

async function testClickjacking(url) {
    const results = { warnings: [], notes: [] };

    try {
        const response = await axios.get(url);
        const headers = response.headers;

        if (!headers['x-frame-options'] && !headers['content-security-policy']) {
            results.warnings.push('No X-Frame-Options or CSP frame restrictions');
            results.notes.push('Website might be vulnerable to clickjacking');
        } else {
            results.notes.push('X-Frame-Options or CSP detected');
        }
    } catch (error) {
        results.notes.push(`Failed to fetch security headers: ${error.message}`);
    }

    return {
        passed: results.warnings.length === 0,
        ...results,
        notes: results.notes.join(', ')
    };
}


async function testSQLInjection(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
        // Test several common SQL injection payloads
        const payloads = [
            "' OR '1'='1",
            "1' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT 1,2,3--",
            "admin'--"
        ];

        const results = [];
        let vulnerable = false;

        for (const payload of payloads) {
            const encodedPayload = encodeURIComponent(payload);
            const response = await fetch(`${url}?id=${encodedPayload}`, {
                method: 'GET',
                credentials: 'include',
                signal: controller.signal
            });

            const content = await response.text();
            const statusCode = response.status;

            // Check for signs of SQL injection vulnerability
            const hasErrorMessage = /SQL|syntax|mysql|oracle|ORA-|postgres/i.test(content);
            const unexpectedSuccess = statusCode === 200 && content.includes("success") && payload.includes("OR");
            const dataLeakage = content.includes("UNION") && /table|column|row/i.test(content);

            if (hasErrorMessage || unexpectedSuccess || dataLeakage) {
                vulnerable = true;
                results.push(`Potential SQL injection with payload: ${payload}`);
            }
        }

        clearTimeout(timeout);

        return {
            passed: !vulnerable,
            warnings: vulnerable ? results : [],
            notes: vulnerable
                ? "The application may be vulnerable to SQL injection. Database error messages or unexpected behavior detected."
                : "No immediate SQL injection vulnerabilities detected. Further manual testing recommended."
        };
    } catch (error) {
        clearTimeout(timeout);
        return {
            passed: false,
            warnings: [`Test failed: ${error.message}`],
            notes: "SQL injection test could not be completed due to connection issues"
        };
    }
}

async function testContentSecurityPolicy(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
        const response = await fetch(url, {
            method: 'GET',
            credentials: 'include',
            signal: controller.signal
        });
        clearTimeout(timeout);

        const headers = response.headers;
        const cspHeader = headers.get('Content-Security-Policy');

        if (!cspHeader) {
            return {
                passed: false,
                warnings: ["No Content Security Policy header detected"],
                notes: "Implement a Content Security Policy to prevent XSS and data injection attacks"
            };
        }

        // Verify CSP has essential directives
        const hasDefaultSrc = /default-src\s+[^;]+;/.test(cspHeader);
        const hasScriptSrc = /script-src\s+[^;]+;/.test(cspHeader);
        const hasUnsafeInline = /unsafe-inline/.test(cspHeader);
        const hasUnsafeEval = /unsafe-eval/.test(cspHeader);
        const hasWildcardSrc = /script-src\s+[^;]*\*/.test(cspHeader);

        const warnings = [];

        if (!hasDefaultSrc) {
            warnings.push("Missing default-src directive in CSP");
        }

        if (!hasScriptSrc) {
            warnings.push("Missing script-src directive in CSP");
        }

        if (hasUnsafeInline) {
            warnings.push("CSP contains unsafe-inline directive which reduces security");
        }

        if (hasUnsafeEval) {
            warnings.push("CSP contains unsafe-eval directive which reduces security");
        }

        if (hasWildcardSrc) {
            warnings.push("CSP contains wildcard (*) in script-src which reduces security");
        }

        return {
            passed: warnings.length === 0,
            warnings: warnings,
            notes: warnings.length === 0
                ? "Content Security Policy is properly implemented"
                : "Content Security Policy exists but has security gaps"
        };
    } catch (error) {
        clearTimeout(timeout);
        return {
            passed: false,
            warnings: [`Test failed: ${error.message}`],
            notes: "CSP test could not be completed due to connection issues"
        };
    }
}

async function testXSS(url) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    try {
        const payload = encodeURIComponent('<img src=x onerror=alert(1)>');
        const response = await fetch(`${url}?test=${payload}`, {
            method: 'GET',
            credentials: 'include',
            signal: controller.signal
        });
        clearTimeout(timeout);

        const content = await response.text();
        const vulnerable = content.includes(payload) || /<script[^>]*>/.test(content);

        return {
            passed: !vulnerable,
            warnings: vulnerable ? ["Reflected XSS detected - input parameters directly reflected in response"] : [],
            notes: vulnerable ? "Unsanitized user input reflected in HTML" : "No immediate XSS reflection detected"
        };
    } catch (error) {
        clearTimeout(timeout);
        return {
            passed: false,
            warnings: [`Test failed: ${error.message}`],
            notes: "XSS test could not be completed due to connection issues"
        };
    }
}

async function testXFrameOptions(url) {
    try {
        const response = await fetch(url, { method: 'HEAD', redirect: 'manual' });
        const header = response.headers.get('x-frame-options') || '';
        const valid = /^(DENY|SAMEORIGIN)$/i.test(header);
        const csp = response.headers.get('content-security-policy') || '';

        return {
            passed: valid || csp.includes('frame-ancestors'),
            warnings: valid ? [] : ['Missing X-Frame-Options or insecure Content-Security-Policy'],
            notes: valid ? `Secure framing policy: ${header}` : `Clickjacking risk - ${csp ? 'CSP present' : 'No frame protection'}`
        };
    } catch (error) {
        return {
            passed: false,
            warnings: [`Header check failed: ${error.message}`],
            notes: "Could not verify frame embedding protections"
        };
    }
}

export async function testPathTraversal(url) {
    const results = { vulnerabilities: [], tested: 0 };

    try {
        const { origin, pathname } = new URL(url);
        const payloads = [
            '../../../../etc/passwd',
            '....//....//etc/passwd',
            '%2e%2e%2f/etc/passwd',
            '..%5c..%5cwindows\\win.ini'
        ];

        for (const payload of payloads) {
            try {
                const testUrl = `${origin}${pathname}?file=${encodeURIComponent(payload)}`;
                const response = await fetch(testUrl, { redirect: 'manual' });

                if (response.status === 200) {
                    const content = await response.text();
                    const vulnerable = content.match(/root:\w+:0:0:/) || content.includes('[boot loader]');
                    if (vulnerable) results.vulnerabilities.push(`Found sensitive data in ${testUrl}`);
                }
                results.tested++;
            } catch (e) { continue; }
        }

        return {
            passed: results.vulnerabilities.length === 0,
            message: results.vulnerabilities.length
                ? `${results.vulnerabilities.length} path traversal vectors found`
                : 'No obvious directory traversal vulnerabilities',
            notes: results.vulnerabilities.length
                ? "Server returns sensitive files when modified path parameters"
                : "No evidence of file system exposure through URL parameters",
            details: results
        };
    } catch (error) {
        return {
            passed: false,
            message: "Path traversal tests failed",
            notes: `Test framework error: ${error.message}`,
            details: results
        };
    }
}

async function testCORS(url) {
    const results = { warnings: [], notes: [] };

    try {
        const { headers } = await axios.options(url, {
            headers: { 'Origin': 'https://attacker.com' },
            maxRedirects: 0
        });

        const acao = headers['access-control-allow-origin'];
        if (acao === '*') {
            results.warnings.push('Any origin allowed');
            results.notes.push('Credentials cannot be sent with wildcard CORS');
        } else if (acao === 'https://attacker.com') {
            results.warnings.push('Origin reflection detected');
            results.notes.push('Server mirrors arbitrary Origin headers');
        }
    } catch (error) {
        results.notes.push(`Preflight failed: ${error.response?.status || error.code}`);
    }

    try {
        const response = await axios.post(url, {}, {
            headers: { 'Origin': 'https://attacker.com' },
            withCredentials: true
        });
        if (response.headers['access-control-allow-credentials'] === 'true') {
            results.warnings.push('Credentials allowed from untrusted origins');
            results.notes.push('Combined with wildcard origin, this allows cross-origin auth');
        }
    } catch (error) {
        results.notes.push(`POST test failed: ${error.response?.status || error.code}`);
    }

    return {
        passed: results.warnings.length === 0,
        ...results,
        notes: results.notes.join(', ')
    };
}

async function testCSRF(url) {
    const results = { warnings: [], notes: [] };

    try {
        const response = await axios.get(url);
        const cookies = response.headers['set-cookie'] || [];
        const samesite = cookies.some(c => c.includes('SameSite'))
            ? "SameSite attributes present"
            : "Missing SameSite on cookies";

        results.notes.push(samesite);
        if (!cookies.some(c => c.includes('SameSite=Strict') || c.includes('SameSite=Lax'))) {
            results.warnings.push('Insecure cookie settings');
        }
    } catch (error) {
        results.notes.push(`Cookie analysis failed: ${error.message}`);
    }

    try {
        await axios.post(url, { payload: 'test' });
        results.warnings.push('POST accepted without CSRF tokens');
        results.notes.push('No apparent anti-CSRF mechanism detected');
    } catch (error) {
        if (error.response?.status === 403) {
            results.notes.push('Server rejected unauthorized POST (possible CSRF protection)');
        }
    }

    return {
        passed: results.warnings.length === 0,
        ...results,
        notes: results.notes.join(', ')
    };
}

export async function run_at(urls, delayMs = 500, logger = console.log) {
    logger("Yo!!!")
    const summary = { processed: 0, failed: 0, results: {} };
    const tests = [testXSS,
        testXFrameOptions, testPathTraversal, testCORS, testCSRF,
        testSQLInjection, testContentSecurityPolicy,
        testSSRF, testInsecureCookies, testClickjacking, testOpenRedirect,
        testSecurityHeaders];

    for (const url of urls) {
        summary.results[url] = {};

        for (const test of tests) {
            console.log(test);

            await delay(delayMs);
            try {
                const result = await test(url);
                summary.results[url][test.name] = result;
                summary.processed++;
                if (!result.passed) summary.failed++;
            } catch (error) {
                summary.results[url][test.name] = {
                    error: error.message,
                    notes: "Test crashed during execution"
                };
                summary.failed++;
            }
        }
    }

    return summary;
}
