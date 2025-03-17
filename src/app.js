import express from 'express';
import { createServer } from 'http';
import { Server } from 'socket.io';
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
const httpServer = createServer(app);
const io = new Server(httpServer);
const PORT = 3001;

function createLogToSocket(socketId) {
    return function logToSocket(message) {
        io.to(socketId).emit('log', message);
    };
}


// Setup socket.io connection
io.on('connection', (socket) => {
    console.log('Client connected:', socket.id);

    socket.on('start-test', async (url) => {
        try {
            const logToSocket = createLogToSocket(socket.id);

            logToSocket('Starting analysis of: ' + url);
            const tempResults = await trackAjaxCalls(url, logToSocket);
            logToSocket('Processing security endpoints...');
            const urls = await processSecurityEndpoints(tempResults);
            logToSocket(`Found endpoint urls to check: ${urls}`);
            console.log(urls);
            
            logToSocket(`Running security tests on ${String(urls)}`);
            let finalRes = await run_at(urls, logToSocket);

            // Send results through socket
            socket.emit('results', finalRes);
        } catch (error) {
            console.error("Error during analysis:", error);
            socket.emit('error', `Error: ${error.message}`);
        }
    });

    socket.on('disconnect', () => {
        console.log('Client disconnected:', socket.id);
    });
});

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve static files (CSS, JS, etc.)
app.use(express.static('public'));


// Modify the /analyze route to work with socket.io too (keep for backward compatibility)
app.post('/analyze', async (req, res) => {
    let { url } = req.body;
    try {
        const tempResults = await trackAjaxCalls(url);
        const urls = await processSecurityEndpoints(tempResults);
        let finalRes = await run_at(urls);
        res.json(finalRes);
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

// Change app.listen to httpServer.listen
httpServer.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});