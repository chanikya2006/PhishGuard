// blocked.js
const urlParams = new URLSearchParams(window.location.search);
const blockedUrl = urlParams.get('url') || 'Unknown URL';
document.getElementById('blockedUrl').innerText = blockedUrl;