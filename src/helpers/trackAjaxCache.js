import fs from 'fs/promises';
// import path from 'path';
import crypto from 'crypto';

import path from 'path';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { trackAjaxCalls } from '../ptLogger.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
// const cacheDir = path.join(__dirname, 'ajax_cache');

// const cacheDir = path.join(__dirname, 'ajax_cache');


/**
 * Wrapper for trackAjaxCalls that implements file-based caching
 * @param {string} url - The URL to track AJAX calls for
 * @returns {Promise<object>} - The results of the tracking operation
 */
export async function trackAjaxCallsWrapper(url) {
    // const fs = require('fs').promises;
    // const path = require('path');
    // const crypto = require('crypto');


    // Create cache directory if it doesn't exist
    const cacheDir = path.join(__dirname, 'ajax_cache');
    try {
        await fs.mkdir(cacheDir, { recursive: true });
    } catch (error) {
        if (error.code !== 'EEXIST') {
            console.error("Error creating cache directory:", error);
            throw error;
        }
    }

    // Generate safe filename from URL using hash
    const getFileName = (url) => {
        const hash = crypto.createHash('md5').update(url).digest('hex');
        return path.join(cacheDir, `${hash}.json`);
    };

    const cacheFile = getFileName(url);
    const TWO_HOURS_MS = 2 * 60 * 60 * 1000;

    // Check if cache exists and is valid
    try {
        const fileStats = await fs.stat(cacheFile);

        // If file exists, read it
        if (fileStats.isFile()) {
            const data = JSON.parse(await fs.readFile(cacheFile, 'utf8'));
            const timestamp = new Date(data.timestamp);
            const now = new Date();

            // Check if cache is still valid (less than 2 hours old)
            if ((now - timestamp) < TWO_HOURS_MS) {
                console.log(`Cache hit for ${url}`);
                return data.results;
            } else {
                console.log(`Cache expired for ${url}`);
            }
        }
    } catch (error) {
        // File doesn't exist or couldn't be read - normal for first-time requests
        if (error.code !== 'ENOENT') {
            console.warn(`Cache read warning for ${url}:`, error.message);
        }
    }

    // If we get here, cache miss or expired - fetch fresh data
    try {
        const results = await trackAjaxCalls(url);

        // Store results in cache
        const cacheData = {
            url: url,
            timestamp: new Date().toISOString(),
            results: results
        };

        await fs.writeFile(cacheFile, JSON.stringify(cacheData, null, 2));
        console.log(`Cached results for ${url}`);

        return results;
    } catch (error) {
        console.error(`Error tracking AJAX calls for ${url}:`, error);
        throw error;
    }
}