// ==UserScript==
// @name         Omni-Eye Lite
// @namespace    https://unit8402.omni-eye
// @version      4.1
// @description  Intelligence modules: Archives, Fingerprint, SQLi, IDOR, APIs, CORS, JWT, PII, CSV
// @author       UNIT 8402
// @license      MIT
// @match        *://*/*
// @icon         data:image/svg+xml,<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="black"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/></svg>
// ==/UserScript==

(function() {
    'use strict';

    const OMNIEYE = {
        version: '4.1',
        targetUrl: window.location.href,
        targetDomain: window.location.hostname,
        archives: [
            'https://web.archive.org/web/',
            'https://webcache.googleusercontent.com/search?q=cache:',
            'https://cc.bingj.com/cache.aspx?q='
        ]
    };

    let resultsDiv = null;

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

    // ========== 1. ARCHIVE ==========
    async function scanArchives() {
        appendResult('Archive', 'Scanning...');
        let found = [];
        for (let archive of OMNIEYE.archives) {
            try {
                let res = await fetch(archive + OMNIEYE.targetUrl);
                if (res.status === 200) {
                    let text = await res.text();
                    let matches = text.match(/\.env|\.git|backup\.zip|\.sql|\.htaccess/gi);
                    if (matches) found.push(`${archive.split('/')[2]}: ${matches.join(', ')}`);
                }
            } catch(e) {}
        }
        if (found.length) appendResult('Archive', 'Found', found);
        else appendResult('Archive', 'Nothing found');
    }

    // ========== 2. DEVELOPER FINGERPRINT ==========
    function scanDeveloper() {
        let html = document.documentElement.innerHTML;
        let emails = html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
        let tools = html.match(/vscode|phpstorm|sublime|webstorm/gi) || [];
        let results = [];
        if (emails.length) results.push(`📧 Emails: ${emails.slice(0,3).join(', ')}`);
        if (tools.length) results.push(`🛠️ Tools: ${[...new Set(tools)].join(', ')}`);
        if (results.length) appendResult('Dev', 'Found', results);
        else appendResult('Dev', 'Nothing found');
    }

    // ========== 3. IDOR SCANNER ==========
    async function scanIDOR() {
        appendResult('IDOR', 'Scanning...');
        let links = document.querySelectorAll('a[href*="id="], a[href*="user_id="], a[href*="page="]');
        let found = [];
        let testIds = [0, 1, 999999];
        for (let link of links) {
            let url = link.href;
            for (let id of testIds) {
                let testUrl = url.replace(/id=\d+/, `id=${id}`).replace(/user_id=\d+/, `user_id=${id}`);
                if (testUrl !== url) {
                    try {
                        let res = await fetch(testUrl, { method: 'HEAD' });
                        if (res.status === 200) {
                            found.push(testUrl);
                            appendResult('IDOR', `⚠️ Potential: ${testUrl}`);
                            break;
                        }
                    } catch(e) {}
                }
            }
        }
        if (!found.length) appendResult('IDOR', 'Nothing found');
    }

    // ========== 4. API DISCOVERY ==========
    function discoverAPIs() {
        let endpoints = new Set();
        document.querySelectorAll('script').forEach(script => {
            let content = script.src ? '' : script.innerHTML;
            let matches = content.match(/\/api\/[a-zA-Z0-9\/\-_]+/g) || [];
            matches.forEach(m => endpoints.add(m));
        });
        if (endpoints.size) appendResult('API', `Found ${endpoints.size}`, Array.from(endpoints).slice(0,5));
        else appendResult('API', 'Nothing found');
    }

    // ========== 5. CORS SCANNER ==========
    async function scanCORS() {
        try {
            let res = await fetch(OMNIEYE.targetUrl);
            let acao = res.headers.get('Access-Control-Allow-Origin');
            if (acao === '*') appendResult('CORS', '⚠️ Dangerous: *');
            else if (acao) appendResult('CORS', `Policy: ${acao}`);
            else appendResult('CORS', 'Secure');
        } catch(e) { appendResult('CORS', 'Error'); }
    }

    // ========== 6. JWT ANALYZER ==========
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
        else appendResult('JWT', 'Nothing found');
    }

    // ========== 7. PII EXTRACTOR ==========
    function extractPII() {
        let text = document.body.innerText;
        let ids = [...new Set(text.match(/\b1\d{9}\b/g) || [])];
        let phones = [...new Set(text.match(/\b05\d{8}\b/g) || [])];
        let emails = [...new Set(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];
        let results = [];
        if (ids.length) results.push(`🆔 IDs: ${ids.slice(0,5).join(', ')}`);
        if (phones.length) results.push(`📞 Phones: ${phones.slice(0,5).join(', ')}`);
        if (emails.length) results.push(`📧 Emails: ${emails.slice(0,5).join(', ')}`);
        if (results.length) appendResult('PII', 'Found', results);
        else appendResult('PII', 'Nothing found');
    }

    // ========== 8. CSV EXPORT (mock) ==========
    function exportMockCSV() {
        let data = [['Type', 'Value', 'URL']];
        data.push(['Example', '1234567890', OMNIEYE.targetUrl]);
        let csv = data.map(row => row.join(',')).join('\n');
        let blob = new Blob([csv], { type: 'text/csv' });
        let url = URL.createObjectURL(blob);
        let a = document.createElement('a');
        a.href = url;
        a.download = `omni-eye-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        appendResult('CSV', 'Exported example data');
    }

    // ========== 9. CREATE UI (delayed) ==========
    function createPanel() {
        const panel = document.createElement('div');
        panel.id = 'omni-eye-panel';
        panel.innerHTML = `
            <div style="position:fixed; bottom:20px; left:20px; width:320px; background:#0a0a0f; color:#00ffaa; border-radius:12px; border:1px solid #00ffaa; z-index:999999; font-family:monospace; font-size:11px; padding:10px;">
                <div style="font-weight:bold; margin-bottom:8px; display:flex; justify-content:space-between;">
                    <span>🔍 Omni-Eye v${OMNIEYE.version}</span>
                    <span id="oe-toggle" style="cursor:pointer;">🗕</span>
                </div>
                <div id="oe-content">
                    <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:4px; margin-bottom:8px;">
                        <button id="oe-arch">📜 Arch</button>
                        <button id="oe-dev">👤 Dev</button>
                        <button id="oe-idor">🎯 IDOR</button>
                        <button id="oe-api">🔌 API</button>
                        <button id="oe-cors">🌐 CORS</button>
                        <button id="oe-jwt">🔑 JWT</button>
                        <button id="oe-pii">🆔 PII</button>
                        <button id="oe-csv">📥 CSV</button>
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
        document.getElementById('oe-idor').onclick = scanIDOR;
        document.getElementById('oe-api').onclick = discoverAPIs;
        document.getElementById('oe-cors').onclick = scanCORS;
        document.getElementById('oe-jwt').onclick = analyzeJWT;
        document.getElementById('oe-pii').onclick = extractPII;
        document.getElementById('oe-csv').onclick = exportMockCSV;
    }

    setTimeout(() => {
        createPanel();
        console.log(`%c✅ Omni-Eye v${OMNIEYE.version} ready`, 'color: #0f0; font-size:14px;');
    }, 500);
})();
