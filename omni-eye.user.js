// ==UserScript==
// @name         Omni-Eye UNIT 8402 v4.2
// @namespace    https://unit8402.omni-eye
// @version      4.2
// @description  Intelligence platform: Archive, Fingerprint, SQLi, IDOR, APIs, CORS, SSRF, GraphQL, JWT, PII, CSV, Live Pulse
// @author       UNIT 8402
// @license      MIT
// @match        *://*/*
// @grant        GM_setValue
// @grant        GM_getValue
// @grant        GM_xmlhttpRequest
// @grant        GM_notification
// @icon         data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="black"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/></svg>
// ==/UserScript==

(function() {
    'use strict';

    const OMNIEYE = {
        version: '4.2',
        db: null,
        targetUrl: window.location.href,
        targetDomain: window.location.hostname,
        archives: [
            'https://web.archive.org/web/',
            'https://webcache.googleusercontent.com/search?q=cache:',
            'https://cc.bingj.com/cache.aspx?q='
        ]
    };

    let resultsDiv = null;
    let piiData = { ids: [], phones: [], emails: [] };
    let vulnsData = [];

    function appendResult(module, status, details = null) {
        if (!resultsDiv) return;
        const timestamp = new Date().toLocaleTimeString();
        let html = `<div style="border-bottom:1px solid #333; padding:4px 0; font-size:10px;">`;
        html += `<span style="color:#0a0;">[${timestamp}]</span> `;
        html += `<span style="color:#ff0;">${module}</span>: `;
        html += `<span style="color:#fff;">${status}</span>`;
        if (details && Array.isArray(details)) {
            html += `<div style="padding-left:10px; color:#aaa;">${details.join('<br>')}</div>`;
        }
        html += `</div>`;
        resultsDiv.insertAdjacentHTML('afterbegin', html);
        while (resultsDiv.children.length > 50) resultsDiv.removeChild(resultsDiv.lastChild);
    }

    // ========== PII EXTRACTOR (AUTOMATIC) ==========
    function extractPII() {
        const text = document.body.innerText;
        const ids = [...new Set(text.match(/\b1\d{9}\b/g) || [])];
        const phones = [...new Set(text.match(/\b05\d{8}\b/g) || [])];
        const emails = [...new Set(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];
        
        piiData = { ids, phones, emails };
        
        let results = [];
        if (ids.length) results.push(`🆔 IDs: ${ids.join(', ')}`);
        if (phones.length) results.push(`📞 Phones: ${phones.join(', ')}`);
        if (emails.length) results.push(`📧 Emails: ${emails.join(', ')}`);
        
        if (results.length) {
            appendResult('PII', `Found ${ids.length + phones.length + emails.length} items`, results);
        } else {
            appendResult('PII', 'No PII found');
        }
        return { ids, phones, emails };
    }

    // ========== IDOR SCANNER ==========
    async function scanIDOR() {
        appendResult('IDOR', 'Scanning...');
        const links = document.querySelectorAll('a[href*="id="], a[href*="user_id="], a[href*="page="]');
        let found = [];
        let testIds = [0, 1, 999999, 123456];
        
        for (let link of links) {
            let url = link.href;
            for (let testId of testIds) {
                let testUrl = url.replace(/id=\d+/, `id=${testId}`).replace(/user_id=\d+/, `user_id=${testId}`);
                if (testUrl !== url) {
                    try {
                        let res = await fetch(testUrl, { method: 'HEAD' });
                        if (res.status === 200) {
                            found.push(testUrl);
                            appendResult('IDOR', `⚠️ Potential: ${testUrl.split('?')[0]}`);
                            vulnsData.push({ type: 'IDOR', url: testUrl, date: new Date().toISOString() });
                            break;
                        }
                    } catch(e) {}
                    await new Promise(r => setTimeout(r, 200));
                }
            }
        }
        if (!found.length) appendResult('IDOR', 'Nothing found');
    }

    // ========== API DISCOVERY ==========
    function discoverAPIs() {
        let endpoints = new Set();
        document.querySelectorAll('script').forEach(script => {
            let content = script.src ? '' : script.innerHTML;
            let matches = content.match(/\/api\/[a-zA-Z0-9\/\-_]+/g) || [];
            matches.forEach(m => endpoints.add(m));
            let graphqlMatches = content.match(/\/graphql|\/gql/gi) || [];
            graphqlMatches.forEach(m => endpoints.add(m));
        });
        if (endpoints.size) {
            appendResult('API', `Found ${endpoints.size} endpoints`, Array.from(endpoints).slice(0,10));
        } else {
            appendResult('API', 'No APIs found');
        }
    }

    // ========== ARCHIVE SCAN ==========
    async function scanArchives() {
        appendResult('Archive', 'Scanning...');
        let found = [];
        for (let archive of OMNIEYE.archives) {
            try {
                let res = await fetch(archive + OMNIEYE.targetUrl);
                if (res.status === 200) {
                    let text = await res.text();
                    let matches = text.match(/\.env|\.git|backup\.zip|\.sql|\.htaccess|config|\.log/gi);
                    if (matches) found.push(`${archive.split('/')[2]}: ${matches.slice(0,3).join(', ')}`);
                }
            } catch(e) {}
        }
        if (found.length) appendResult('Archive', 'Found', found);
        else appendResult('Archive', 'Nothing found');
    }

    // ========== DEVELOPER FINGERPRINT ==========
    function scanDeveloper() {
        let html = document.documentElement.innerHTML;
        let emails = html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
        let tools = html.match(/vscode|phpstorm|sublime|webstorm|atom/gi) || [];
        let comments = html.match(/\/\/|<!--|#|FIXME|TODO|HACK/gi) || [];
        
        let results = [];
        if (emails.length) results.push(`📧 Emails: ${emails.slice(0,3).join(', ')}`);
        if (tools.length) results.push(`🛠️ Tools: ${[...new Set(tools)].join(', ')}`);
        if (comments.length) results.push(`💬 Comments: ${comments.length} found`);
        
        if (results.length) appendResult('Dev', 'Found', results);
        else appendResult('Dev', 'Nothing found');
    }

    // ========== CORS SCANNER ==========
    async function scanCORS() {
        try {
            let res = await fetch(OMNIEYE.targetUrl);
            let acao = res.headers.get('Access-Control-Allow-Origin');
            if (acao === '*') appendResult('CORS', '⚠️ Dangerous: * allows any origin');
            else if (acao) appendResult('CORS', `Policy: ${acao}`);
            else appendResult('CORS', 'Secure (no wildcard)');
        } catch(e) { appendResult('CORS', 'Could not check'); }
    }

    // ========== JWT ANALYZER ==========
    function analyzeJWT() {
        let found = [];
        let tokens = document.cookie.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g) || [];
        found.push(...tokens);
        for (let i = 0; i < localStorage.length; i++) {
            let val = localStorage.getItem(localStorage.key(i));
            if (val && val.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g)) {
                found.push(...val.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g));
            }
        }
        if (found.length) appendResult('JWT', `Found ${found.length} tokens`);
        else appendResult('JWT', 'No JWT tokens');
    }

    // ========== SQLi SCANNER (THERMAL) ==========
    async function scanSQLi() {
        appendResult('SQLi', 'Scanning for SQL injection...');
        const links = document.querySelectorAll('a[href*="id="], a[href*="page="]');
        let found = [];
        for (let link of links) {
            let url = link.href;
            let testPayloads = ["1' OR '1'='1", "1' AND '1'='1"];
            for (let payload of testPayloads) {
                let testUrl = url.replace(/id=\d+/, `id=${payload}`).replace(/page=\d+/, `page=${payload}`);
                if (testUrl !== url) {
                    try {
                        let start = performance.now();
                        await fetch(testUrl);
                        let attackTime = performance.now() - start;
                        await fetch(url);
                        let normalTime = performance.now() - start;
                        if (attackTime > normalTime + 200) {
                            found.push(url);
                            appendResult('SQLi', `⚠️ Potential: ${url.split('?')[0]}`);
                            vulnsData.push({ type: 'SQLi', url: url, date: new Date().toISOString() });
                            break;
                        }
                    } catch(e) {}
                    await new Promise(r => setTimeout(r, 500));
                }
            }
        }
        if (!found.length) appendResult('SQLi', 'Nothing found');
    }

    // ========== SSRF TESTER ==========
    async function scanSSRF() {
        appendResult('SSRF', 'Checking for SSRF vectors...');
        const inputs = document.querySelectorAll('input[type="url"], input[name*="url"], input[name*="link"]');
        appendResult('SSRF', `Found ${inputs.length} potential inputs. Manual testing recommended.`);
    }

    // ========== GRAPHQL INTROSPECTION ==========
    async function scanGraphQL() {
        appendResult('GraphQL', 'Checking for introspection...');
        let endpoints = ['/graphql', '/gql', '/v1/graphql', '/api/graphql'];
        for (let endpoint of endpoints) {
            let fullUrl = window.location.origin + endpoint;
            try {
                let res = await fetch(fullUrl, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ query: '{ __schema { types { name } } }' })
                });
                if (res.status === 200) {
                    let data = await res.json();
                    if (data.data && data.data.__schema) {
                        appendResult('GraphQL', `⚠️ Exposed at ${endpoint} with ${data.data.__schema.types.length} types`);
                        vulnsData.push({ type: 'GraphQL', url: endpoint, date: new Date().toISOString() });
                    }
                }
            } catch(e) {}
        }
        appendResult('GraphQL', 'Scan complete');
    }

    // ========== CSV EXPORT (REAL) ==========
    function exportCSV() {
        let csvRows = [['Type', 'Value', 'URL', 'Date']];
        
        piiData.ids.forEach(id => csvRows.push(['ID', id, OMNIEYE.targetUrl, new Date().toISOString()]));
        piiData.phones.forEach(phone => csvRows.push(['Phone', phone, OMNIEYE.targetUrl, new Date().toISOString()]));
        piiData.emails.forEach(email => csvRows.push(['Email', email, OMNIEYE.targetUrl, new Date().toISOString()]));
        vulnsData.forEach(v => csvRows.push([v.type, v.url, OMNIEYE.targetUrl, v.date]));
        
        if (csvRows.length === 1) {
            csvRows.push(['Info', 'No data collected yet', OMNIEYE.targetUrl, new Date().toISOString()]);
        }
        
        let csvContent = csvRows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');
        let blob = new Blob(["\uFEFF" + csvContent], { type: 'text/csv;charset=utf-8;' });
        let url = URL.createObjectURL(blob);
        let a = document.createElement('a');
        a.href = url;
        a.download = `omni-eye-${OMNIEYE.targetDomain}-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        appendResult('CSV', `Exported ${csvRows.length - 1} records`);
    }

    // ========== UI PANEL ==========
    function createPanel() {
        const panel = document.createElement('div');
        panel.id = 'omni-eye-panel';
        panel.innerHTML = `
            <div style="position:fixed; bottom:20px; left:20px; width:340px; max-width:90vw; background:#0a0a0f; color:#00ffaa; border-radius:12px; border:1px solid #00ffaa; z-index:999999; font-family:monospace; font-size:11px; padding:10px; backdrop-filter:blur(10px); box-shadow:0 0 20px rgba(0,255,0,0.1);">
                <div style="font-weight:bold; margin-bottom:8px; border-bottom:1px solid #00ffaa; padding-bottom:5px; display:flex; justify-content:space-between;">
                    <span>🕵️ Omni-Eye v${OMNIEYE.version} | UNIT 8402</span>
                    <span id="oe-toggle" style="cursor:pointer;">🗕</span>
                </div>
                <div id="oe-content">
                    <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:4px; margin-bottom:8px;">
                        <button id="oe-arch" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">📜 Arch</button>
                        <button id="oe-dev" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">👤 Dev</button>
                        <button id="oe-sqli" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">🌡️ SQLi</button>
                        <button id="oe-idor" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">🎯 IDOR</button>
                        <button id="oe-api" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">🔌 API</button>
                        <button id="oe-cors" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">🌐 CORS</button>
                        <button id="oe-ssrf" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">🌍 SSRF</button>
                        <button id="oe-gql" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">📊 GQL</button>
                        <button id="oe-jwt" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">🔑 JWT</button>
                        <button id="oe-pii" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">🆔 PII</button>
                        <button id="oe-csv" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px;">📥 CSV</button>
                    </div>
                    <div id="oe-results" style="height:200px; overflow-y:auto; background:#000; border-radius:6px; padding:5px; border:1px solid #333; font-size:10px;">
                        <div>⚡ Ready</div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(panel);
        
        let content = document.getElementById('oe-content');
        let toggle = document.getElementById('oe-toggle');
        if (toggle) toggle.onclick = () => { content.style.display = content.style.display === 'none' ? 'block' : 'none'; };
        
        resultsDiv = document.getElementById('oe-results');
        
        document.getElementById('oe-arch').onclick = scanArchives;
        document.getElementById('oe-dev').onclick = scanDeveloper;
        document.getElementById('oe-sqli').onclick = scanSQLi;
        document.getElementById('oe-idor').onclick = scanIDOR;
        document.getElementById('oe-api').onclick = discoverAPIs;
        document.getElementById('oe-cors').onclick = scanCORS;
        document.getElementById('oe-ssrf').onclick = scanSSRF;
        document.getElementById('oe-gql').onclick = scanGraphQL;
        document.getElementById('oe-jwt').onclick = analyzeJWT;
        document.getElementById('oe-pii').onclick = extractPII;
        document.getElementById('oe-csv').onclick = exportCSV;
        
        // Auto-extract PII on page load
        setTimeout(() => { extractPII(); }, 1000);
    }

    setTimeout(() => {
        createPanel();
        console.log(`%c✅ Omni-Eye v${OMNIEYE.version} | UNIT 8402 | Ready`, 'color: #0f0; font-size:14px;');
    }, 500);
})();
