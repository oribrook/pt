import express from 'express';
import fs from 'fs'; // 'fs' is a built-in module
import path from 'path';
import { fileURLToPath } from 'url';
import { extractDataFetchingUrls, trackAjaxCalls } from './ptLogger.js';
import { run_at } from './at.js';
import { processSecurityEndpoints } from './filterAjaxCalls.js';
import { trackAjaxCallsWrapper } from './helpers/trackAjaxCache.js';

// Get the directory name for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 3001;


app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (CSS, JS, etc.)
app.use(express.static('public'));


// Route to handle form submission
app.post('/analyze', async (req, res) => {
    let { url } = req.body;
    try {
        const tempResults = await trackAjaxCalls(url);
        // const tempResults = await trackAjaxCallsWrapper(url);

        const urls = await processSecurityEndpoints(tempResults);
        let finalRes = await run_at(urls);
        res.json(finalRes)
        return;

    } catch (error) {
        console.error("Error during analysis:", error);
        res.status(500).send(`Error: ${error.message}`);
    }
});

// Route to serve the HTML form
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Create logs directory if it doesn't exist
const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});