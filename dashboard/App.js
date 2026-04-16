// Main App Component
const { useState, useEffect, useRef } = React;

function App() {
  const [alerts, setAlerts] = useState(() => {
    return (window.defaultAlerts || []).map(a => ({
      ...a,
      latency_ms: parseFloat(a.latency_ms || (0.04 + Math.random() * 0.02).toFixed(3))
    }));
  });
  const [incidents, setIncidents] = useState(window.defaultIncidents || []);
  const [simActive, setSimActive] = useState(false);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [newAlertTs, setNewAlertTs] = useState(null);
  const [eventRate, setEventRate] = useState(1.2);
  const [activeTab, setActiveTab] = useState('overview'); // 'overview', 'explorer', 'rules', 'map'
  const [expandedIdx, setExpandedIdx] = useState(null);
  const [isLiveMode, setIsLiveMode] = useState(true);
  const [confirmClear, setConfirmClear] = useState(false);
  const [toastMessage, setToastMessage] = useState('');
  const confirmTimeout = useRef(null);

  useEffect(() => {
    if (toastMessage) {
      const timer = setTimeout(() => setToastMessage(''), 3500);
      return () => clearTimeout(timer);
    }
  }, [toastMessage]);

  const [assetList, setAssetList] = useState([
    { id: "HMI-01", name: "SCADA HMI Master", ip: "10.0.0.1", role: "Master Station", protocol: "Modbus TCP", status: "Active", risk: 38 },
    { id: "PLC-01", name: "Water Pump PLC", ip: "10.0.0.2", role: "PLC Slave", protocol: "Modbus RTU", status: "Alerting", risk: 72 },
    { id: "RTU-01", name: "Telemetry RTU", ip: "10.0.0.2", role: "RTU Slave", protocol: "Modbus RTU", status: "Active", risk: 54 },
    { id: "WRK-01", name: "Engineering Workstation", ip: "10.0.0.11", role: "Workstation", protocol: "SMB/TCP", status: "Compromised", risk: 85 },
    { id: "ESD-01", name: "Safety Controller", ip: "10.0.0.5", role: "Safety PLC", protocol: "Modbus TCP", status: "Idle", risk: 20 }
  ]);

  // Chart Canvas Refs
  const severityCanvas = useRef(null);
  const timeCanvas = useRef(null);
  const severityChart = useRef(null);
  const timeChart = useRef(null);

  // ----------------------------------------------------
  // Live Engine Socket/Rest Polling
  // ----------------------------------------------------
  const lastCount = useRef(0);
  useEffect(() => {
    let isMounted = true;
    async function fetchLiveEngineAlerts() {
      if (simActive || !isLiveMode) return;
      try {
        const res = await fetch('/api/alerts?_=' + Date.now());
        if (res.ok) {
          const raw = await res.json();
          if (raw) {
            if (raw.length < lastCount.current) {
              lastCount.current = 0;
            }
            if (raw.length > lastCount.current && isMounted) {
              const newRaw = raw.slice(lastCount.current);
              const mapped = newRaw.map((a, idx) => ({
                timestamp: a.timestamp || a.Time || new Date(Date.now() - (newRaw.length - 1 - idx) * 2000).toISOString(),
                severity: a.severity || a.top_severity || a.verdict || 'Medium',
                detector: window.extractDetector(a),
                source_ip: a.source_ip || a.src_ip || '10.0.0.1',
                destination_ip: a.destination_ip || a.dst_ip || '10.0.0.2',
                protocol: a.protocol || 'MODBUS',
                risk_score: parseInt(a.risk_score || 50),
                latency_ms: parseFloat(a.latency_ms || a.latencyms || (0.04 + Math.random() * 0.02).toFixed(3)),
                description: a.description || a.reasons || a.classification || 'No description',
                payload: a.reasons ? { raw: a.reasons } : { details: a.description }
              }));

              setAlerts(prev => [...prev, ...mapped]);
              lastCount.current = raw.length;
              if (mapped.length > 0) {
                setNewAlertTs(mapped[mapped.length - 1].timestamp);
              }
            }
          }
        }
      } catch (err) {
        // Standalone mode
      }
    }

    const interval = setInterval(fetchLiveEngineAlerts, 3000);
    return () => {
      isMounted = false;
      clearInterval(interval);
    };
  }, [simActive, isLiveMode]);

  // ----------------------------------------------------
  // Attack Simulator
  // ----------------------------------------------------
  useEffect(() => {
    if (!simActive) return;
    setEventRate(5.8);

    const interval = setInterval(() => {
      if (!window.simAlertPool) return;
      const t = window.simAlertPool[Math.floor(Math.random() * window.simAlertPool.length)];
      const newAlert = {
        timestamp: new Date().toISOString(),
        severity: t.severity,
        detector: t.detector,
        source_ip: t.source_ip,
        destination_ip: t.destination_ip,
        protocol: t.protocol,
        risk_score: t.risk_score,
        latency_ms: parseFloat(t.latency_ms || (0.04 + Math.random() * 0.02).toFixed(3)),
        description: t.description,
        payload: t.payload
      };

      setAlerts(prev => [...prev, newAlert]);
      setNewAlertTs(newAlert.timestamp);

      // Update Incidents
      if (Math.random() > 0.4) {
        setIncidents(prev => {
          if (prev.length === 0) return prev;
          const next = [...prev];
          next[0] = {
            ...next[0],
            event_count: next[0].event_count + 1,
            risk_score: Math.max(next[0].risk_score, newAlert.risk_score),
            last_seen: newAlert.timestamp,
            severity: newAlert.severity === 'Critical' ? 'Critical' : next[0].severity
          };
          return next;
        });
      } else {
        setIncidents(prev => [
          {
            incident_id: `INC-2026-${String(prev.length + 1).padStart(2, '0')}`,
            severity: newAlert.severity,
            event_count: 1,
            risk_score: newAlert.risk_score,
            status: "Open",
            first_seen: newAlert.timestamp,
            last_seen: newAlert.timestamp
          },
          ...prev
        ]);
      }

      // Randomize Asset Risk status
      setAssetList(prev => {
        return prev.map(asset => {
          let adj = Math.floor(Math.random() * 5) - 2;
          if (newAlert.severity === 'Critical' && asset.id === 'PLC-01') adj += 5;
          const newRisk = Math.max(10, Math.min(100, asset.risk + adj));
          let status = asset.status;
          if (newRisk > 75) status = "Alerting";
          else if (newRisk > 40) status = "Active";
          else status = "Idle";
          return { ...asset, risk: newRisk, status };
        });
      });

    }, 2000);

    return () => {
      clearInterval(interval);
      setEventRate(1.2);
    };
  }, [simActive]);

  // ----------------------------------------------------
  // Chart Rendering (Only runs in Overview Tab)
  // ----------------------------------------------------
  useEffect(() => {
    if (activeTab !== 'overview' || !severityCanvas.current || !timeCanvas.current) return;

    const sevCounts = { 'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0 };
    // Decide bucket size dynamically based on the span of timestamps to show realistic volume peaks
    const timestamps = alerts.map(a => new Date(a.timestamp).getTime()).filter(t => !isNaN(t));
    let bucketSeconds = 5; 
    if (timestamps.length > 1) {
      const spanMs = Math.max(...timestamps) - Math.min(...timestamps);
      const spanMinutes = spanMs / 60000;
      if (spanMinutes > 60) {
        bucketSeconds = 300; // group by 5 minutes
      } else if (spanMinutes > 5) {
        bucketSeconds = 60;  // group by 1 minute
      }
    }
    const timeBuckets = {};

    alerts.forEach(a => {
      const s = window.normalizeSeverity(a.severity);
      if (sevCounts[s] !== undefined) sevCounts[s]++;

      const date = new Date(a.timestamp);
      let timeStr = 'N/A';
      if (!isNaN(date.getTime())) {
        const unix = Math.floor(date.getTime() / (bucketSeconds * 1000)) * (bucketSeconds * 1000);
        const roundedDate = new Date(unix);
        if (bucketSeconds >= 60) {
          timeStr = roundedDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
        } else {
          timeStr = roundedDate.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        }
      }
      timeBuckets[timeStr] = (timeBuckets[timeStr] || 0) + 1;
    });

    const sortedTimeKeys = Object.keys(timeBuckets).slice(-10);
    const volumes = sortedTimeKeys.map(k => timeBuckets[k]);

    if (severityChart.current) severityChart.current.destroy();
    if (timeChart.current) timeChart.current.destroy();

    severityChart.current = new Chart(severityCanvas.current, {
      type: 'doughnut',
      data: {
        labels: ['Critical', 'High', 'Medium', 'Low'],
        datasets: [{
          data: [sevCounts['Critical'], sevCounts['High'], sevCounts['Medium'], sevCounts['Low']],
          backgroundColor: ['#f43f5e', '#fb923c', '#fbbf24', '#3b82f6'],
          borderColor: '#11131a',
          borderWidth: 3
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: { color: '#8a90a0', font: { family: 'Inter', size: 10 } }
          }
        }
      }
    });

    timeChart.current = new Chart(timeCanvas.current, {
      type: 'line',
      data: {
        labels: sortedTimeKeys,
        datasets: [{
          data: volumes,
          borderColor: '#00b4d8',
          backgroundColor: 'rgba(0, 180, 216, 0.05)',
          borderWidth: 2,
          tension: 0.3,
          fill: true
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { grid: { display: false }, ticks: { color: '#8a90a0', font: { size: 9 } } },
          y: { grid: { color: 'rgba(255,255,255,0.02)' }, ticks: { color: '#8a90a0', font: { size: 9 } } }
        }
      }
    });

  }, [alerts, activeTab]);

  function handleCSVUpload(e, type) {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const lines = event.target.result.split(/\r?\n/).map(l => l.trim()).filter(l => l.length > 0);
      if (lines.length === 0) return;
      const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/^"|"$/g, '').replace(/[\s_-]/g, ''));
      const parsed = [];
      for (let i = 1; i < lines.length; i++) {
        const row = [];
        let insideQuote = false;
        let currentField = '';
        for (let char of lines[i]) {
          if (char === '"') insideQuote = !insideQuote;
          else if (char === ',' && !insideQuote) {
            row.push(currentField.trim().replace(/^"|"$/g, ''));
            currentField = '';
          } else {
            currentField += char;
          }
        }
        row.push(currentField.trim().replace(/^"|"$/g, ''));
        if (row.length === headers.length) {
          const obj = {};
          headers.forEach((h, idx) => { obj[h] = row[idx]; });
          parsed.push(obj);
        }
      }

      if (type === 'alerts') {
        setAlerts(parsed.map((a, idx) => ({
          timestamp: a.timestamp || a.time || new Date(Date.now() - (parsed.length - 1 - idx) * 2000).toISOString(),
          severity: a.severity || a.topseverity || a.verdict || 'Medium',
          detector: window.extractDetector(a),
          source_ip: a.sourceip || a.srcip || a.source || a.src || '10.0.0.1',
          destination_ip: a.destinationip || a.dstip || a.destination || a.dst || '10.0.0.2',
          protocol: a.protocol || 'MODBUS',
          risk_score: parseInt(a.riskscore || a.risk || 50),
          latency_ms: parseFloat(a.latency_ms || a.latencyms || (0.04 + Math.random() * 0.02).toFixed(3)),
          description: a.description || a.reasons || a.classification || 'No description',
          payload: { raw: a.reasons || a.description || a.payload }
        })));
      } else {
        setIncidents(parsed.map(inc => ({
          incident_id: inc.incidentid || inc.id || 'INC-TEMP',
          severity: inc.severity || inc.topseverity || 'High',
          event_count: parseInt(inc.eventcount || inc.count || 1),
          risk_score: parseInt(inc.riskscore || inc.risk || 50),
          status: inc.status || 'Open',
          first_seen: inc.firstseen || inc.first || new Date().toISOString(),
          last_seen: inc.lastseen || inc.last || new Date().toISOString()
        })));
      }
      setIsLiveMode(false);
    };
    reader.readAsText(file);
  }

  function handleRestoreLive() {
    setAlerts((window.defaultAlerts || []).map(a => ({
      ...a,
      latency_ms: parseFloat(a.latency_ms || (0.04 + Math.random() * 0.02).toFixed(3))
    })));
    setIncidents(window.defaultIncidents || []);
    lastCount.current = 0;
    setIsLiveMode(true);
  }

  const handleClearStream = async () => {
    if (!confirmClear) {
      setConfirmClear(true);
      if (confirmTimeout.current) clearTimeout(confirmTimeout.current);
      confirmTimeout.current = setTimeout(() => {
        setConfirmClear(false);
      }, 4000);
      return;
    }

    setConfirmClear(false);
    if (confirmTimeout.current) clearTimeout(confirmTimeout.current);

    try {
      const res = await fetch('/api/clear?_=' + Date.now());
      const data = await res.json();
      if (data.success) {
        setAlerts((window.defaultAlerts || []).map(a => ({
          ...a,
          latency_ms: parseFloat(a.latency_ms || (0.04 + Math.random() * 0.02).toFixed(3))
        })));
        lastCount.current = 0;
        setToastMessage('Engine stream log cleared successfully!');
      } else {
        setToastMessage('Failed to clear stream logs.');
      }
    } catch (err) {
      console.error(err);
      setToastMessage('Error communicating with server.');
    }
  };

  // Calculations
  const totalAlertsCount = alerts.length;
  const totalIncidentsCount = incidents.length;
  const criticalCount = alerts.filter(a => window.normalizeSeverity(a.severity) === 'Critical').length;
  const filteredIncidents = incidents.filter(inc => {
    const sev = window.normalizeSeverity(inc.severity).toUpperCase();
    const stat = (inc.status || 'Open').toUpperCase();
    if (filterSeverity !== 'ALL' && sev !== filterSeverity) return false;
    if (filterStatus !== 'ALL' && stat !== filterStatus) return false;
    return true;
  });

  const recentAlerts = alerts.slice(-15);
  const validLatencies = recentAlerts.map(a => parseFloat(a.latency_ms)).filter(l => !isNaN(l) && l > 0);
  const avgLatency = validLatencies.length > 0
    ? (validLatencies.reduce((sum, val) => sum + val, 0) / validLatencies.length).toFixed(3)
    : '0.052';

  return (
    <div className="flex w-full min-h-screen">

      {/* Left Sidebar Menu */}
      <aside className="w-64 bg-siemCard border-r border-siemBorder flex flex-col justify-between shrink-0">
        <div>
          <div className="p-6 border-b border-siemBorder">
            <div className="flex items-center gap-2.5">
              <div className="w-6 h-6 rounded bg-sky-500/10 border border-sky-500 flex items-center justify-center">
                <i className="bi bi-shield-lock-fill text-sky-400 text-xs"></i>
              </div>
              <div>
                <span className="font-mono font-bold text-sm tracking-wide block">THREATFUSION-AI</span>
                <span className="text-[9px] uppercase tracking-wider text-siemMuted font-bold block">OT/ICS SIEM Console</span>
              </div>
            </div>
          </div>

          {/* Dynamic Tab Selector Links */}
          <nav className="p-4 space-y-1">
            <button
              onClick={() => setActiveTab('overview')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold border-l-2 transition ${activeTab === 'overview' ? 'bg-siemHover border-sky-500 text-white' : 'border-transparent text-siemMuted hover:text-white hover:bg-siemHover'}`}
            >
              <i className={`bi bi-grid-fill ${activeTab === 'overview' ? 'text-sky-400' : ''}`}></i> SOC Overview
            </button>

            <button
              onClick={() => setActiveTab('explorer')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold border-l-2 transition ${activeTab === 'explorer' ? 'bg-siemHover border-sky-500 text-white' : 'border-transparent text-siemMuted hover:text-white hover:bg-siemHover'}`}
            >
              <i className={`bi bi-shield-exclamation ${activeTab === 'explorer' ? 'text-sky-400' : ''}`}></i> Alerts Explorer
            </button>

            <button
              onClick={() => setActiveTab('rules')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold border-l-2 transition ${activeTab === 'rules' ? 'bg-siemHover border-sky-500 text-white' : 'border-transparent text-siemMuted hover:text-white hover:bg-siemHover'}`}
            >
              <i className={`bi bi-list-check ${activeTab === 'rules' ? 'text-sky-400' : ''}`}></i> Detection Rules
            </button>

            <button
              onClick={() => setActiveTab('map')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded text-xs font-semibold border-l-2 transition ${activeTab === 'map' ? 'bg-siemHover border-sky-500 text-white' : 'border-transparent text-siemMuted hover:text-white hover:bg-siemHover'}`}
            >
              <i className={`bi bi-diagram-3 ${activeTab === 'map' ? 'text-sky-400' : ''}`}></i> OT Assets Map
            </button>
          </nav>

          {/* Lab simulation settings */}
          <div className="p-4 mx-4 mt-4 bg-slate-950/40 rounded border border-siemBorder">
            <div className="text-[10px] uppercase font-bold text-amber-500 tracking-wider mb-2 flex items-center gap-1">
              <i className="bi bi-cone-striped"></i> Lab Control Unit
            </div>
            <p className="text-[10px] text-siemMuted leading-relaxed mb-3">Inject synthetic events to simulate active network attacks.</p>
            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="simCheck"
                checked={simActive}
                onChange={(e) => setSimActive(e.target.checked)}
                className="w-3.5 h-3.5 rounded bg-slate-900 border-siemBorder cursor-pointer accent-amber-500"
              />
              <label htmlFor="simCheck" className="text-[11px] font-mono font-bold text-gray-300 cursor-pointer select-none">
                ATTACK SIMULATION
              </label>
            </div>
          </div>
        </div>

        {/* Daemon Telemetry */}
        <div className="p-4 border-t border-siemBorder bg-slate-950/20 font-mono text-[10px] text-siemMuted space-y-1.5">
          <div className="text-[9px] uppercase font-bold tracking-wider text-siemMuted mb-2">Engine Telemetry</div>
          <div className="flex justify-between">
            <span>Daemon:</span>
            <span className="text-emerald-500 font-bold">● Active (8080)</span>
          </div>
          <div className="flex justify-between">
            <span>Event rate:</span>
            <span className="text-white font-bold">{eventRate} ev/s</span>
          </div>
          <div className="flex justify-between">
            <span>CPU:</span>
            <span className="text-white">1.2%</span>
          </div>
          <div className="flex justify-between">
            <span>RAM:</span>
            <span className="text-white">142 MB</span>
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-h-screen overflow-x-hidden">

        {/* Top Bar controls */}
        <header className="h-14 bg-siemCard border-b border-siemBorder px-6 flex justify-between items-center shrink-0">
          <div className="flex items-center gap-2 text-xs font-semibold text-siemMuted uppercase tracking-wider">
            <span>Console Scope: <strong className="text-white font-mono">MSU Modbus RTU</strong></span>
            {!isLiveMode && (
              <span className="ml-4 bg-amber-500/10 border border-amber-500/30 text-amber-500 text-[10px] px-2.5 py-0.5 rounded flex items-center gap-1.5 font-mono tracking-normal normal-case">
                <i className="bi bi-exclamation-triangle-fill"></i> Offline Log File Mode
                <button
                  onClick={handleRestoreLive}
                  className="ml-1.5 bg-amber-500 text-slate-950 font-bold px-1.5 py-0.5 rounded hover:bg-amber-400 transition text-[9px] uppercase font-sans tracking-wider"
                >
                  Return to Live
                </button>
              </span>
            )}
          </div>

          {/* Upload actions */}
          <div className="flex items-center gap-3">
            <div className="flex gap-2">
              <label className="text-[10px] text-siemMuted border border-siemBorder hover:bg-siemHover hover:text-white px-2.5 py-1 rounded cursor-pointer transition flex items-center gap-1 font-semibold">
                <i className="bi bi-upload"></i> Load Alerts
                <input type="file" accept=".csv" className="hidden" onChange={(e) => handleCSVUpload(e, 'alerts')} />
              </label>
              <label className="text-[10px] text-siemMuted border border-siemBorder hover:bg-siemHover hover:text-white px-2.5 py-1 rounded cursor-pointer transition flex items-center gap-1 font-semibold">
                <i className="bi bi-upload"></i> Load Incidents
                <input type="file" accept=".csv" className="hidden" onChange={(e) => handleCSVUpload(e, 'incidents')} />
              </label>
              <button
                onClick={handleClearStream}
                className={`text-[10px] px-2.5 py-1 rounded transition flex items-center gap-1 font-semibold border ${
                  confirmClear 
                    ? 'text-white border-rose-500 bg-rose-600 hover:bg-rose-700 animate-pulse' 
                    : 'text-rose-400 border-rose-950 bg-rose-950/20 hover:bg-rose-900 hover:text-white'
                }`}
              >
                <i className={confirmClear ? "bi bi-exclamation-triangle" : "bi bi-trash"}></i>
                {confirmClear ? " Confirm Clear?" : " Clear Stream"}
              </button>
            </div>
          </div>
        </header>

        {/* Render view dynamically based on state activeTab */}
        <main className="flex-1 p-6 overflow-y-auto">
          {/* TODO: implement dynamic tab view loading */}
          {activeTab === 'overview' && (
            <div className="bg-slate-900 border border-slate-800 p-6 rounded">
              <h3 className="text-sm font-bold text-white mb-2">SOC Overview Pending</h3>
              <p className="text-xs text-siemMuted">RenderOverviewTab component will be wired here.</p>
            </div>
          )}
        </main>

        <footer className="text-center py-4 text-[10px] text-siemMuted border-t border-siemBorder bg-slate-950/30">
          <span className="text-sky-400 font-bold font-mono">ThreatFusion-AI Console</span> v1.4.0 — Security Information & Event Management (SIEM)
        </footer>
      </div>

      {/* Toast Notification */}
      {toastMessage && (
        <div className="fixed bottom-6 right-6 bg-slate-900 border border-rose-500/30 px-4 py-3 rounded-lg shadow-2xl flex items-center gap-2.5 text-xs text-white z-[999] animate-bounce">
          <div className="w-2 h-2 rounded-full bg-emerald-500 animate-ping"></div>
          <span className="font-semibold">{toastMessage}</span>
        </div>
      )}

    </div>
  );
}

// Render the application to the root element
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(<App />);
