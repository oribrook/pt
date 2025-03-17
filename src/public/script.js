const socket = io();

function addLog(message) {
    const logsDiv = document.getElementById("logs");
    const logEntry = document.createElement("div");
    logEntry.className = "log-entry";
    logEntry.textContent = message;
    logsDiv.appendChild(logEntry);
    logsDiv.scrollTop = logsDiv.scrollHeight;
}

// Setup socket event listeners
socket.on('connect', () => {
    console.log('Connected to server');
});

socket.on('log', (message) => {
    addLog(message);
});

socket.on('results', (data) => {
    displayResult(data);
    showLoading(false);
});

socket.on('error', (message) => {
    showNotification(message, "error");
    showLoading(false);
});

// async function runTest() {
//     const url = document.getElementById("urlInput").value.trim();
//     if (!url) {
//         showNotification("Please enter a valid URL", "error");
//         return;
//     }

//     try {
//         showLoading(true);
//         const response = await fetch("/analyze", {
//             method: "POST",
//             headers: { "Content-Type": "application/json" },
//             body: JSON.stringify({ url })
//         });
        
//         const data = await response.json();
//         displayResult(data);
//     } catch (error) {
//         showNotification("An error occurred while analyzing the URL", "error");
//     } finally {
//         showLoading(false);
//     }
// }

// Modify runTest to use socket.io
async function runTest() {
    const url = document.getElementById("urlInput").value.trim();
    if (!url) {
        showNotification("Please enter a valid URL", "error");
        return;
    }

    try {
        showLoading(true);
        // Clear previous logs and results
        document.getElementById("logs").innerHTML = "";
        document.getElementById("result").innerHTML = "";
        
        // Emit start-test event
        socket.emit('start-test', url);
    } catch (error) {
        showNotification("An error occurred while analyzing the URL", "error");
        showLoading(false);
    }
}


function displayResult(data) {
    const resultDiv = document.getElementById("result");
    resultDiv.innerHTML = `
        <div class="result-summary">
            <h2>Analysis Results</h2>
            <div class="stats-grid">
                <div class="stat-card">
                    <span class="stat-value">${data.processed}</span>
                    <span class="stat-label">Processed</span>
                </div>
                <div class="stat-card fail">
                    <span class="stat-value">${data.failed}</span>
                    <span class="stat-label">Failed</span>
                </div>
            </div>
        </div>
    `;

    Object.entries(data.results).forEach(([site, tests], index) => {
        let details = `
            <div class="result-card" style="animation-delay: ${index * 0.1}s">
                <h3>${site}</h3>
                <ul class="test-list">`;
        
        Object.entries(tests).forEach(([test, result]) => {
            const status = result.passed ? "pass" : "fail";
            const warnings = result.warnings?.length ? `<p class="warning">${result.warnings.join(", ")}</p>` : "";
            const notes = result.notes ? `<p class="notes">${result.notes}</p>` : "";
            const message = result.message ? `<p class="message">${result.message}</p>` : "";

            details += `
                <li class="test-item">
                    <div class="test-header">
                        <span class="test-name">${test}</span>
                        <span class="status ${status}">${status.toUpperCase()}</span>
                        <button class="toggle-btn" onclick="toggleDetails(this)">+</button>
                    </div>
                    <div class="details">
                        ${message}${warnings}${notes}
                    </div>
                </li>`;
        });
        details += `</ul></div>`;
        resultDiv.innerHTML += details;
    });
}

function toggleDetails(button) {
    const details = button.parentElement.nextElementSibling;
    const isExpanded = button.textContent === "-";
    
    button.textContent = isExpanded ? "+" : "-";
    details.classList.toggle("show");
}

function showNotification(message, type) {
    const notification = document.createElement("div");
    notification.className = `notification ${type}`;
    notification.textContent = message;
    document.body.appendChild(notification);
    
    setTimeout(() => notification.remove(), 3000);
}

function showLoading(show) {
    let loading = document.getElementById("loading");
    if (!loading && show) {
        loading = document.createElement("div");
        loading.id = "loading";
        loading.innerHTML = '<div class="spinner"></div>';
        document.body.appendChild(loading);
    } else if (loading && !show) {
        loading.remove();
    }
}