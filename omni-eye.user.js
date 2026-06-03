// ==UserScript==
// @name         YouTube Cookies Exporter (UNIT 8402)
// @namespace    http://tampermonkey.net/
// @version      1.0
// @description  Extract YouTube LOGIN_INFO cookie in Netscape format
// @author       UNIT 8402
// @match        *://www.youtube.com/*
// @grant        none
// ==/UserScript==

(function() {
    'use strict';
    console.log("✅ UNIT 8402: Cookie Exporter script loaded");
    
    // إضافة زر في صفحة يوتيوب
    const btn = document.createElement('button');
    btn.innerHTML = '📁 Export Cookies.txt';
    btn.style.position = 'fixed';
    btn.style.bottom = '20px';
    btn.style.right = '20px';
    btn.style.zIndex = 9999;
    btn.style.padding = '12px 16px';
    btn.style.backgroundColor = '#ff0000';
    btn.style.color = 'white';
    btn.style.border = 'none';
    btn.style.borderRadius = '8px';
    btn.style.fontWeight = 'bold';
    btn.style.cursor = 'pointer';
    btn.style.boxShadow = '0 2px 5px rgba(0,0,0,0.3)';
    document.body.appendChild(btn);

    btn.addEventListener('click', () => {
        console.log("🖱️ Button clicked");
        let cookies = document.cookie.split(';');
        let loginInfo = cookies.find(c => c.trim().startsWith('LOGIN_INFO='));

        if (loginInfo) {
            let value = loginInfo.split('=')[1];
            let cookieContent = `# Netscape HTTP Cookie File\n.youtube.com\tTRUE\t/\tTRUE\t0\tLOGIN_INFO\t${value}`;
            let blob = new Blob([cookieContent], {type: 'text/plain'});
            let a = document.createElement('a');
            let url = URL.createObjectURL(blob);
            a.href = url;
            a.download = 'cookies.txt';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            alert('✅ cookies.txt exported successfully!');
        } else {
            alert('❌ LOGIN_INFO not found. Make sure you are logged in to YouTube.');
        }
    });
})();