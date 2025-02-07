const FIREWALL_ENDPOINT = 'https://your-flask-server.com/analyze';

// Track request counts
let requestCounts = new Map();

chrome.webRequest.onBeforeRequest.addListener(async (details) => {
    const srcIp = details.ip || 'unknown';
    const requestData = {
        url: details.url,
        src_ip: srcIp,
        method: details.method,
        content_length: details.requestBody?.size || 0,
        protocol: details.type,
        request_count: updateRequestCount(srcIp)
    };

    try {
        const response = await fetch(FIREWALL_ENDPOINT, {
            method: 'POST',
            body: JSON.stringify(requestData),
            headers: {'Content-Type': 'application/json'}
        });
        
        const result = await response.json();
        if (result.action === 'block') {
            return { cancel: true };
        }
    } catch (error) {
        console.error('Firewall error:', error);
    }
    return { cancel: false };
}, { urls: ["<all_urls>"] }, ["blocking", "requestBody"]);

function updateRequestCount(ip) {
    const count = (requestCounts.get(ip) || 0) + 1;
    requestCounts.set(ip, count);
    return count;
}