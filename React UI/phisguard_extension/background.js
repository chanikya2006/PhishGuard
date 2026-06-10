const BACKEND = "http://127.0.0.1:8000/predict";

// List of domains to NEVER block (whitelist)
const WHITELIST_DOMAINS = [
    "google.com", "accounts.google.com", "ogs.google.com",
    "github.com", "stackoverflow.com", "leetcode.com",
    "youtube.com", "microsoft.com", "amazon.com","iitg.ac.in","online.iitg.ac.in"
];

// Helper: check if a domain is whitelisted
function isWhitelisted(url) {
    try {
        const hostname = new URL(url).hostname;
        return WHITELIST_DOMAINS.some(domain => hostname === domain || hostname.endsWith(`.${domain}`));
    } catch (e) {
        return false;
    }
}

// Helper: check if we should skip this URL
function shouldSkipUrl(url) {
    if (!url) return true;
    if (url.startsWith("chrome://") || url.startsWith("about:") || url.startsWith("edge://")) return true;
    if (url === "" || url === "about:blank") return true;
    if (isWhitelisted(url)) return true;
    return false;
}

// Only check MAIN FRAME navigations
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
    if (details.frameId !== 0) return;
    const url = details.url;
    if (shouldSkipUrl(url)) return;
    
    console.log("PhishGuard checking:", url);
    
    fetch(BACKEND, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(data => {
        if (data.final_verdict === "phishing") {
            // 🔴 Show red badge with "!" on the extension icon
            chrome.action.setBadgeText({ text: "!", tabId: details.tabId });
            chrome.action.setBadgeBackgroundColor({ color: "#f44336", tabId: details.tabId });
            
            // Clear the badge after 3 seconds
            setTimeout(() => {
                chrome.action.setBadgeText({ text: "", tabId: details.tabId });
            }, 3000);
            
            // Redirect to blocked page
            chrome.tabs.update(details.tabId, {
                url: chrome.runtime.getURL("blocked.html") + "?url=" + encodeURIComponent(url)
            });
        } else {
            // Store for popup display
            chrome.storage.local.set({ [url]: data });
        }
    })
    .catch(err => console.error("PhishGuard error:", err));
});