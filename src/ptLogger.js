import puppeteer from "puppeteer";

/**
 * Tracks all AJAX calls, clicks interactive elements, and logs API interactions.
 * @param {string} url - The target URL to analyze.
 * @param {number} [maxRequests=50] - Max number of requests to track.
 * @param {number} [maxTime=30000] - Max execution time in milliseconds.
 * @param {boolean} [headless=true] - Run in headless mode or not.
 * @returns {Promise<Object>} - Returns an object containing detected endpoints and errors.
 */
export async function trackAjaxCalls(url, maxRequests = 50, maxTime = 30000, headless = true) {
    const browser = await puppeteer.launch({
        headless: headless ? 'new' : false // Use new headless mode
    });
    const page = await browser.newPage();
    const results = { endpoints: [], errors: [] };
    let requestCount = 0;
    const startTime = Date.now();

    // Set up request interception
    await page.setRequestInterception(true);

    // Track requests
    page.on('request', request => {
        if (requestCount >= maxRequests || (Date.now() - startTime) > maxTime) {
            request.abort();
            return;
        }

        const requestData = {
            url: request.url(),
            method: request.method(),
            type: request.resourceType(),
            requestHeaders: request.headers(),
            requestBody: request.postData() || null
        };

        results.endpoints.push(requestData);
        requestCount++;
        request.continue();
    });

    // Track responses
    page.on('response', async response => {
        try {
            const request = response.request();
            const matchedEndpoint = results.endpoints.find(e => e.url === request.url());

            if (matchedEndpoint) {
                matchedEndpoint.responseStatus = response.status();
                matchedEndpoint.responseHeaders = response.headers();

                const contentType = response.headers()['content-type'] || '';
                if (contentType.includes('application/json')) {
                    try {
                        matchedEndpoint.responseBody = await response.json();
                    } catch (error) {
                        matchedEndpoint.responseBody = null;
                    }
                }
            }
        } catch (error) {
            results.errors.push({ message: 'Response processing failed', error: error.message });
        }
    });

    try {
        // Navigate to page
        await page.goto(url, { waitUntil: 'networkidle2', timeout: maxTime });

        // Find interactive elements
        const clickableElements = await page.$$('a, button, [onclick], input[type="submit"], [role="button"], .btn');

        // Click elements one by one
        for (let element of clickableElements) {
            if ((Date.now() - startTime) > maxTime) break;

            try {
                // Check if element is visible and clickable
                const isVisible = await page.evaluate(el => {
                    const style = window.getComputedStyle(el);
                    return style && style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
                }, element);

                if (isVisible) {
                    // Scroll element into view
                    await element.evaluate(el => el.scrollIntoView({ behavior: 'smooth', block: 'center' }));
                    await page.waitForTimeout(300);

                    // Click and wait for any network activity
                    await Promise.race([
                        element.click({ delay: 100 }),
                        page.waitForNavigation({ waitUntil: 'networkidle0', timeout: 3000 }).catch(() => { })
                    ]);

                    await page.waitForTimeout(500);
                }
            } catch (error) {
                results.errors.push({ message: 'Click failed', error: error.message });
            }
        }
    } catch (error) {
        results.errors.push({ message: 'Page interaction failed', error: error.message });
    } finally {
        await browser.close();
    }

    return results;
}

/**
 * Extracts all AJAX and form-submit requests from tracked data.
 * @param {Object} data - The data object returned by trackAjaxCalls.
 * @returns {Array<string>} - Array of URLs that are AJAX or form-submit requests.
 */
export function extractDataFetchingUrls(data) {
    const ajaxAndFormUrls = [];

    if (!data?.endpoints || !Array.isArray(data.endpoints)) {
        return ajaxAndFormUrls;
    }

    data.endpoints.forEach(endpoint => {
        if (!endpoint || !endpoint.url) return;

        const method = endpoint?.method?.toUpperCase() || "";
        

        // Check if this is an AJAX request or form submission
        const isAjaxRequest = endpoint.type === "xmlhttprequest" || endpoint.type === "fetch";
        const isFormSubmit = method === "POST" &&
            (endpoint.requestHeaders?.['content-type']?.includes('application/x-www-form-urlencoded') ||
                endpoint.requestHeaders?.['Content-Type']?.includes('application/x-www-form-urlencoded'));

        // Exclude static resources like images, CSS, fonts, etc.
        const isStaticResource = endpoint.type &&
            ["image", "font", "stylesheet", "script", "other"].includes(endpoint.type);

        if ((isAjaxRequest || isFormSubmit) && !isStaticResource) {
            ajaxAndFormUrls.push(endpoint.url);
        }
    });
    // ajaxAndFormUrls = [...new Set(ajaxAndFormUrls)];

    return [...new Set(ajaxAndFormUrls)];
}