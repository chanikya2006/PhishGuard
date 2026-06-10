import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { ThreeDots } from 'react-loader-spinner';
import './App.css';

const API_BASE = process.env.REACT_APP_API_URL

function App() {
  const [history, setHistory] = useState([]);
  const [stats, setStats] = useState({});
  const [loading, setLoading] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');
  const [currentPage, setCurrentPage] = useState(1);
  const [expandedRow, setExpandedRow] = useState(null);
  const rowsPerPage = 10;

  const fetchData = async () => {
    try {
      const [historyRes, statsRes] = await Promise.all([
        axios.get(`${API_BASE}/history?limit=200`),
        axios.get(`${API_BASE}/stats`)
      ]);
      setHistory(historyRes.data);
      setStats(statsRes.data);
    } catch (err) {
      console.error("Dashboard fetch error:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData();
    let interval;
    if (autoRefresh) {
      interval = setInterval(fetchData, 10000);
    }
    return () => clearInterval(interval);
  }, [autoRefresh]);

  const exportCSV = () => {
    window.open(`${API_BASE}/export`);
  };

  const totalScans = history.length;
  const phishingCount = history.filter(s => s.final_verdict === 'phishing').length;
  const legitimateCount = history.filter(s => s.final_verdict === 'legitimate').length;
  const phishingRate = totalScans ? ((phishingCount / totalScans) * 100).toFixed(1) : 0;

  // Threat intelligence metrics
  const typosquatCount = history.filter(s => s.threat_intelligence?.is_typosquatting === 1).length;
  const newDomainCount = history.filter(s => s.threat_intelligence?.is_newly_registered === 1).length;
  const homoglyphCount = history.filter(s => s.threat_intelligence?.has_homoglyph === 1).length;
  const punycodeCount = history.filter(s => s.threat_intelligence?.has_punycode === 1).length;

  const pieData = Object.entries(stats).map(([name, value]) => ({ name, value }));
  const COLORS = ['#ff6b6b', '#4ecdc4'];

  const filteredHistory = history.filter(scan =>
    scan.url.toLowerCase().includes(searchTerm.toLowerCase())
  );
  const totalPages = Math.ceil(filteredHistory.length / rowsPerPage);
  const paginatedHistory = filteredHistory.slice(
    (currentPage - 1) * rowsPerPage,
    currentPage * rowsPerPage
  );

  const toggleRow = (id) => {
    setExpandedRow(expandedRow === id ? null : id);
  };

  return (
    <div className="dashboard-container">
      {/* Header */}
      <div className="dashboard-header">
        <div className="logo-section">
          <div className="logo-icon">🛡️</div>
          <div className="logo-text">PhishGuard</div>
          <div className="badge">Analyst Console</div>
        </div>
        <div className="header-actions">
          <button className="export-btn" onClick={exportCSV}>
            📥 Export CSV
          </button>
          <label className="auto-refresh-label">
            <input 
              type="checkbox" 
              checked={autoRefresh} 
              onChange={(e) => setAutoRefresh(e.target.checked)} 
            />
            Auto-refresh (10s)
          </label>
        </div>
      </div>

      {/* Metrics Cards */}
      <div className="metrics-grid">
        <div className="metric-card">
          <div className="metric-title">Total Scans</div>
          <div className="metric-value">{totalScans}</div>
          <div className="metric-trend">All time</div>
        </div>
        <div className="metric-card phishing">
          <div className="metric-title">Phishing Detected</div>
          <div className="metric-value">{phishingCount}</div>
          <div className="metric-trend">{phishingRate}% of scans</div>
        </div>
        <div className="metric-card legitimate">
          <div className="metric-title">Legitimate</div>
          <div className="metric-value">{legitimateCount}</div>
          <div className="metric-trend">{100 - phishingRate}% of scans</div>
        </div>
        <div className="metric-card threat">
          <div className="metric-title">Typosquatting</div>
          <div className="metric-value">{typosquatCount}</div>
          <div className="metric-trend">Suspicious domains</div>
        </div>
        <div className="metric-card threat">
          <div className="metric-title">Newly Registered</div>
          <div className="metric-value">{newDomainCount}</div>
          <div className="metric-trend">&lt; 90 days old</div>
        </div>
        <div className="metric-card threat">
          <div className="metric-title">Homoglyph / Punycode</div>
          <div className="metric-value">{homoglyphCount + punycodeCount}</div>
          <div className="metric-trend">Obfuscation</div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="charts-row">
        <div className="chart-card">
          <h3>Risk Distribution</h3>
          <ResponsiveContainer width="100%" height={280}>
            <PieChart>
              <Pie data={pieData} dataKey="value" nameKey="name" cx="50%" cy="50%" outerRadius={90} label>
                {pieData.map((entry, idx) => (
                  <Cell key={idx} fill={COLORS[idx % COLORS.length]} />
                ))}
              </Pie>
              <Tooltip />
            </PieChart>
          </ResponsiveContainer>
        </div>
        <div className="chart-card">
          <h3>Scan Activity (Last 10)</h3>
          <ResponsiveContainer width="100%" height={280}>
            <BarChart data={history.slice(0, 10).map(s => ({ 
              name: new Date(s.timestamp).toLocaleTimeString(), 
              confidence: s.ml_confidence 
            }))}>
              <XAxis dataKey="name" tick={{ fontSize: 10 }} />
              <YAxis domain={[0, 1]} tickFormatter={(v) => `${v * 100}%`} />
              <Tooltip formatter={(v) => `${(v * 100).toFixed(1)}%`} />
              <Legend />
              <Bar dataKey="confidence" fill="#4ecdc4" name="ML Confidence" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* History Table with Threat Intelligence Expandable Rows */}
      <div className="history-section">
        <div className="history-header">
          <h3>Scan History</h3>
          <input 
            type="text" 
            placeholder="🔍 Filter by URL..." 
            className="search-input"
            value={searchTerm}
            onChange={(e) => { setSearchTerm(e.target.value); setCurrentPage(1); }}
          />
        </div>
        {loading ? (
          <div className="loader-container">
            <ThreeDots color="#4ecdc4" height={80} width={80} />
          </div>
        ) : (
          <>
            <div className="table-wrapper">
              <table className="history-table">
                <thead>
                  <tr>
                    <th>URL</th>
                    <th>Timestamp</th>
                    <th>Verdict</th>
                    <th>Confidence</th>
                    <th>URLhaus</th>
                    <th>Threat Intel</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedHistory.map(scan => (
                    <React.Fragment key={scan.id}>
                      <tr>
                        <td className="url-cell">{scan.url}</td>
                        <td>{new Date(scan.timestamp).toLocaleString()}</td>
                        <td className={`verdict ${scan.final_verdict}`}>{scan.final_verdict}</td>
                        <td>{(scan.ml_confidence * 100).toFixed(1)}%</td>
                        <td>{scan.urlhaus_malicious ? '⚠️ Yes' : '✅ No'}</td>
                        <td className="threat-summary">
                          {!scan.threat_intelligence?.is_typosquatting && !scan.threat_intelligence?.is_newly_registered && 
                           !scan.threat_intelligence?.has_homoglyph && !scan.threat_intelligence?.has_punycode && '—'}
                        </td>
                        <td>
                          <button className="details-btn" onClick={() => toggleRow(scan.id)}>
                            {expandedRow === scan.id ? '▲' : '▼'}
                          </button>
                        </td>
                      </tr>
                      {expandedRow === scan.id && (
                        <tr className="details-row">
                          <td colSpan="7">
                            <div className="threat-details">
                              <div className="details-section">
                                <h4>🔍 URL Obfuscation</h4>
                                <div>Decoded: <code>{scan.threat_intelligence?.decoded_url || scan.url}</code></div>
                                <div>Hex Encoding: {scan.threat_intelligence?.has_hex_encoding ? 'Yes' : 'No'}</div>
                                <div>Homoglyph: {scan.threat_intelligence?.has_homoglyph ? '⚠️ Yes' : 'No'}</div>
                                <div>Punycode: {scan.threat_intelligence?.has_punycode ? '⚠️ Yes' : 'No'}</div>
                                <div>Encoding Layers: {scan.threat_intelligence?.encoding_layers || 0}</div>
                              </div>
                              <div className="details-section">
                                <h4>🌐 DNS & WHOIS</h4>
                                <div>DNS Resolves: {scan.threat_intelligence?.dns_resolves ? 'Yes' : 'No'}</div>
                                <div>MX Record: {scan.threat_intelligence?.has_mx_record ? 'Yes' : 'No'}</div>
                                <div>IP Address: {scan.threat_intelligence?.ip_address || '—'}</div>
                                <div>Domain Age: {scan.threat_intelligence?.domain_age_days !== undefined ? `${scan.threat_intelligence.domain_age_days} days` : '—'}</div>
                                <div>Newly Registered (&lt;90d): {scan.threat_intelligence?.is_newly_registered ? '⚠️ Yes' : 'No'}</div>
                                <div>Expires Soon: {scan.threat_intelligence?.expires_soon ? '⚠️ Yes' : 'No'}</div>
                              </div>
                              <div className="details-section">
                                <h4>✍️ Typosquatting</h4>
                                <div>Detected: {scan.threat_intelligence?.is_typosquatting ? '⚠️ Yes' : 'No'}</div>
                                {scan.threat_intelligence?.is_typosquatting && (
                                  <>
                                    <div>Target: {scan.threat_intelligence.typosquatting_target}</div>
                                    <div>Similarity Score: {scan.threat_intelligence.typosquatting_score}</div>
                                  </>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                  {paginatedHistory.length === 0 && (
                    <tr><td colSpan="7" className="no-data">No scans found</td></tr>
                  )}
                </tbody>
              </table>
            </div>
            {totalPages > 1 && (
              <div className="pagination">
                <button disabled={currentPage === 1} onClick={() => setCurrentPage(p => p-1)}>← Previous</button>
                <span>Page {currentPage} of {totalPages}</span>
                <button disabled={currentPage === totalPages} onClick={() => setCurrentPage(p => p+1)}>Next →</button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default App;
