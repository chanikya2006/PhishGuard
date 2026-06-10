document.getElementById('checkBtn').addEventListener('click', () => {
  const statusText = document.getElementById('statusText');
  const statusIcon = document.getElementById('statusIcon');
  const confidenceSpan = document.getElementById('confidenceSpan');
  const card = document.getElementById('statusCard');

  statusText.innerHTML = '<span class="loader"></span> Scanning...';
  statusIcon.innerText = '🔍';
  confidenceSpan.innerText = '—';
  card.className = 'status-card';

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;
    if (!url.startsWith('http')) {
      statusText.innerText = 'Not a web page';
      statusIcon.innerText = '🌐';
      confidenceSpan.innerText = 'N/A';
      return;
    }

    fetch('https://phishguard-qtm4.onrender.com/predict', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: url })
    })
    .then(res => res.json())
    .then(data => {
      if (data.final_verdict === 'phishing') {
        statusText.innerText = '⚠️ PHISHING DETECTED';
        statusIcon.innerText = '⛔';
        card.className = 'status-card phish';
        confidenceSpan.innerText = `Confidence: ${(data.ml_confidence * 100).toFixed(1)}%`;
      } else {
        statusText.innerText = '✅ SAFE';
        statusIcon.innerText = '🛡️';
        card.className = 'status-card safe';
        confidenceSpan.innerText = `Confidence: ${(data.ml_confidence * 100).toFixed(1)}%`;
      }
    })
    .catch(() => {
      statusText.innerText = 'Connection error';
      statusIcon.innerText = '⚠️';
      confidenceSpan.innerText = 'Backend offline?';
    });
  });
});

// Auto-check when popup opens
window.addEventListener('DOMContentLoaded', () => {
  document.getElementById('checkBtn').click();
});