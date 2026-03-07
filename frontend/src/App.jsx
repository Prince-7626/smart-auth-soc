import React, { useState, useEffect, useRef } from 'react';
import { io } from 'socket.io-client';
import axios from 'axios';
import { Shield, AlertTriangle, Activity, Lock, Search, Settings, Server, Users, Terminal } from 'lucide-react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import './App.css';

const socket = io();

// Initial dummy data for the chart to make it look alive immediately
const initialChartData = Array.from({ length: 20 }, (_, i) => ({
  time: new Date(Date.now() - (20 - i) * 2000).toLocaleTimeString([], { hour12: false }),
  attacks: Math.floor(Math.random() * 5),
}));

function App() {
  const [metrics, setMetrics] = useState({
    total_failed: 0,
    unique_ips: 0,
    blocked_ips: 0,
    ml_alerts: 0,
  });

  const [threats, setThreats] = useState([]);
  const [chartData, setChartData] = useState(initialChartData);
  const [activeTab, setActiveTab] = useState('Dashboard');
  const [logs, setLogs] = useState([]);
  const logsEndRef = useRef(null);

  useEffect(() => {
    // Initial fetch of historical threats
    axios.get('/api/incidents').then((res) => {
      setThreats(res.data.slice(0, 50));
    }).catch(err => console.error("API Error", err));

    axios.get('/api/dashboard-data').then((res) => {
      setMetrics(res.data);
    }).catch(err => console.error("API Error", err));

    // Socket listeners
    socket.on('connect', () => {
      addLog('SYSTEM', 'Connected to secure WebSocket stream. Monitoring active.');
    });

    socket.on('metrics_update', (data) => {
      setMetrics(data);
    });

    socket.on('new_threat', (data) => {
      setThreats(prev => [data, ...prev].slice(0, 100));

      // Add to chart
      const time = new Date().toLocaleTimeString([], { hour12: false });
      setChartData(prev => {
        const newData = [...prev, { time, attacks: data.severity === 'CRITICAL' ? 15 : (data.severity === 'HIGH' ? 8 : 4) }];
        return newData.slice(-20); // Keep last 20 points
      });

      // Add to live tail
      addLog(data.severity, `Threat detected from ${data.ip} (${data.location}): ${data.reason}`);
    });

    return () => {
      socket.off('connect');
      socket.off('metrics_update');
      socket.off('new_threat');
    };
  }, []);

  // Auto-scroll the tiny terminal
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  const addLog = (type, message) => {
    const time = new Date().toLocaleTimeString();
    setLogs(prev => [...prev, { time, type, message }].slice(-50));
  };

  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    const formData = new FormData();
    formData.append('file', file);

    try {
      addLog('SYSTEM', `Uploading ${file.name}...`);
      const response = await axios.post('/api/logs/upload', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
        withCredentials: true
      });
      addLog('SUCCESS', response.data.message);
    } catch (error) {
      addLog('ERROR', `Upload failed: ${error.response?.data?.error || error.message}`);
    }

    // reset file input
    event.target.value = null;
  };

  const getSeverityColor = (severity) => {
    switch (severity?.toUpperCase()) {
      case 'CRITICAL': return 'var(--danger-color)';
      case 'HIGH': return 'var(--warning-color)';
      case 'MEDIUM': return 'var(--accent-color)';
      default: return 'var(--text-muted)';
    }
  };

  return (
    <div className="soc-app">
      {/* Sidebar */}
      <nav className="soc-sidebar">
        <div className="sidebar-logo">
          <Shield size={28} className="logo-icon" />
          <span>SMART<b>AUTH</b></span>
        </div>
        <ul className="sidebar-menu">
          <li className={activeTab === 'Dashboard' ? 'active' : ''} onClick={() => setActiveTab('Dashboard')}><Activity size={20} /> Dashboard</li>
          <li className={activeTab === 'Incidents' ? 'active' : ''} onClick={() => setActiveTab('Incidents')}><AlertTriangle size={20} /> Incidents</li>
          <li className={activeTab === 'UEBA Analytics' ? 'active' : ''} onClick={() => setActiveTab('UEBA Analytics')}><Users size={20} /> UEBA Analytics</li>
          <li className={activeTab === 'Firewall Rules' ? 'active' : ''} onClick={() => setActiveTab('Firewall Rules')}><Lock size={20} /> Firewall Rules</li>
          <li className={activeTab === 'System Logs' ? 'active' : ''} onClick={() => setActiveTab('System Logs')}><Server size={20} /> System Logs</li>
        </ul>
        <div className="sidebar-bottom">
          <Settings size={20} className="settings-icon" />
        </div>
      </nav>

      {/* Main Content */}
      <main className="soc-main">
        <header className="soc-header">
          <div className="header-title">
            <h1>Security Operations Center</h1>
            <span className="live-indicator"><span className="pulse"></span> LIVE</span>
          </div>
          <div className="header-search">
            <Search size={16} />
            <input type="text" placeholder="Search IPs, events, or rules..." />
          </div>
          <div className="header-user">
            <img src="https://ui-avatars.com/api/?name=Admin&background=1f2937&color=eff6ff" alt="User" />
          </div>
        </header>

        <div className="soc-content">
          {activeTab === 'Dashboard' && (
            <>
              {/* Top Metrics Row */}
              <div className="metrics-grid">
                <div className="metric-card">
                  <div className="metric-header">
                    <h3>Failed Attempts</h3>
                    <Activity size={18} className="text-muted" />
                  </div>
                  <div className="metric-value">{metrics.total_failed}</div>
                  <div className="metric-trend positive">Real-Time Sync</div>
                </div>
                <div className="metric-card">
                  <div className="metric-header">
                    <h3>Unique IPs</h3>
                    <Users size={18} className="text-muted" />
                  </div>
                  <div className="metric-value">{metrics.unique_ips}</div>
                  <div className="metric-trend">Global Sources</div>
                </div>
                <div className="metric-card danger">
                  <div className="metric-header">
                    <h3>Blocked IPs (WAF)</h3>
                    <Lock size={18} />
                  </div>
                  <div className="metric-value">{metrics.blocked_ips}</div>
                  <div className="metric-trend negative">Active blocks</div>
                </div>
                <div className="metric-card ueba">
                  <div className="metric-header">
                    <h3>UEBA Anomalies</h3>
                    <AlertTriangle size={18} />
                  </div>
                  <div className="metric-value">{metrics.ml_alerts}</div>
                  <div className="metric-trend warning">AI Interventions</div>
                </div>
              </div>

              <div className="middle-grid">
                {/* Chart Section */}
                <div className="panel chart-panel">
                  <div className="panel-header">
                    <h2>Attack Volume (Last 60s)</h2>
                  </div>
                  <div className="chart-container">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={chartData} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <defs>
                          <linearGradient id="colorAttacks" x1="0" y1="0" x2="0" y2="1">
                            <stop offset="5%" stopColor="#ef4444" stopOpacity={0.8} />
                            <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                          </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#334155" />
                        <XAxis dataKey="time" stroke="#94a3b8" fontSize={12} tickMargin={10} />
                        <YAxis stroke="#94a3b8" fontSize={12} tickLine={false} axisLine={false} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1e293b', border: '1px solid #334155', borderRadius: '4px' }}
                          itemStyle={{ color: '#f8fafc' }}
                        />
                        <Area type="monotone" dataKey="attacks" stroke="#ef4444" strokeWidth={3} fillOpacity={1} fill="url(#colorAttacks)" />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>

                {/* Live Terminal Section */}
                <div className="panel terminal-panel">
                  <div className="panel-header">
                    <h2>Live Tailing <Terminal size={14} style={{ marginLeft: '8px' }} /></h2>
                  </div>
                  <div className="terminal-window">
                    {logs.map((log, i) => (
                      <div key={i} className={`log-line ${log.type?.toLowerCase()}`}>
                        <span className="log-time">[{log.time}]</span>
                        <span className="log-type">[{log.type}]</span>
                        <span className="log-msg">{log.message}</span>
                      </div>
                    ))}
                    <div ref={logsEndRef} />
                  </div>
                </div>
              </div>
            </>
          )}

          {/* Incidents View */}
          {activeTab === 'Incidents' && (
            <div className="panel threats-panel">
              <div className="panel-header">
                <h2>Recent Threat Intelligence Events</h2>
                <button className="export-btn">Export CSV</button>
              </div>
              <div className="table-container">
                <table className="soc-table">
                  <thead>
                    <tr>
                      <th>Timestamp</th>
                      <th>Severity</th>
                      <th>Source IP</th>
                      <th>Location</th>
                      <th>Reason</th>
                    </tr>
                  </thead>
                  <tbody>
                    {threats.map((threat, idx) => (
                      <tr key={idx} className="threat-row">
                        <td className="time-col">{new Date().toLocaleTimeString()}</td>
                        <td>
                          <span className={`badge badge-${threat.severity?.toLowerCase()}`}>
                            {threat.severity}
                          </span>
                        </td>
                        <td className="ip-col">{threat.ip}</td>
                        <td>{threat.location}</td>
                        <td className="reason-col">{threat.reason}</td>
                      </tr>
                    ))}
                    {threats.length === 0 && (
                      <tr>
                        <td colSpan="5" className="empty-state">No recent threats detected. Monitoring active...</td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Additional Stub Pages */}
          {activeTab === 'UEBA Analytics' && (
            <div className="metrics-grid" style={{ marginTop: '20px' }}>
              <div className="metric-card ueba" style={{ gridColumn: 'span 4' }}>
                <h3>UEBA Anomalies</h3>
                <div className="metric-value">{metrics.ml_alerts}</div>
                <p style={{ marginTop: '10px', color: 'var(--text-muted)' }}>Historical UEBA metrics have not yet been fully populated by the ML engine. Please see live incidents for real-time anomalous user behavior.</p>
              </div>
            </div>
          )}

          {activeTab === 'Firewall Rules' && (
            <div className="panel" style={{ marginTop: '20px' }}>
              <div className="panel-header"><h2>Active WAF Blocks</h2></div>
              <div style={{ padding: '20px' }}>
                <div className="metric-value">{metrics.blocked_ips} IPs currently blocked</div>
                <p style={{ marginTop: '10px', color: 'var(--text-muted)' }}>The auto-scaling firewall rules are actively rejecting connections from these unique IPv4 sources across global endpoints in zero-trust mode.</p>
              </div>
            </div>
          )}

          {activeTab === 'System Logs' && (
            <div className="panel terminal-panel" style={{ marginTop: '20px', height: '600px' }}>
              <div className="panel-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <h2>System Event Logs <Terminal size={14} style={{ marginLeft: '8px' }} /></h2>
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <label htmlFor="log-upload" className="export-btn" style={{ cursor: 'pointer', margin: 0, padding: '6px 12px', fontSize: '13px' }}>
                    Upload Log File
                  </label>
                  <input
                    id="log-upload"
                    type="file"
                    accept=".log,.txt"
                    style={{ display: 'none' }}
                    onChange={handleFileUpload}
                  />
                </div>
              </div>
              <div className="terminal-window" style={{ height: 'calc(100% - 60px)' }}>
                {logs.map((log, i) => (
                  <div key={i} className={`log-line ${log.type?.toLowerCase()}`}>
                    <span className="log-time">[{log.time}]</span>
                    <span className="log-type">[{log.type}]</span>
                    <span className="log-msg">{log.message}</span>
                  </div>
                ))}
                <div ref={logsEndRef} />
              </div>
            </div>
          )}

        </div>
      </main >
    </div >
  );
}

export default App;
