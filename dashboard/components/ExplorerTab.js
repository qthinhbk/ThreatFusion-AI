// Alerts Explorer Tab Component
function RenderExplorerTab({ alerts }) {
  const [localSearch, setLocalSearch] = React.useState('');
  const [localSev, setLocalSev] = React.useState('ALL');
  const [localDet, setLocalDet] = React.useState('ALL');
  const [expIdx, setExpIdx] = React.useState(null);
  const [currentPage, setCurrentPage] = React.useState(1);
  const itemsPerPage = 20;

  // Reset page on filter changes
  const handleSearchChange = (val) => {
    setLocalSearch(val);
    setCurrentPage(1);
    setExpIdx(null);
  };
  const handleSevChange = (val) => {
    setLocalSev(val);
    setCurrentPage(1);
    setExpIdx(null);
  };
  const handleDetChange = (val) => {
    setLocalDet(val);
    setCurrentPage(1);
    setExpIdx(null);
  };

  const filtered = alerts.filter(a => {
    if (localSev !== 'ALL' && window.normalizeSeverity(a.severity).toUpperCase() !== localSev) return false;
    if (localDet !== 'ALL' && a.detector !== localDet) return false;
    if (localSearch) {
      const s = localSearch.toLowerCase();
      return a.detector.toLowerCase().includes(s) || 
             a.source_ip.includes(s) || 
             a.destination_ip.includes(s) || 
             a.description.toLowerCase().includes(s);
    }
    return true;
  });

  const totalPages = Math.ceil(filtered.length / itemsPerPage) || 1;
  const activePage = Math.min(currentPage, totalPages);
  const startIndex = (activePage - 1) * itemsPerPage;
  
  // Slice current page of reversed items
  const reversedFiltered = [...filtered].reverse();
  const paginatedAlerts = reversedFiltered.slice(startIndex, startIndex + itemsPerPage);

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-lg font-bold text-white">Alerts Explorer</h2>
        <p className="text-xs text-siemMuted">Deep search and telemetry payload inspection for all detected events</p>
      </div>

      {/* Filters Card */}
      <div className="bg-siemCard border border-siemBorder rounded p-4 grid grid-cols-1 md:grid-cols-3 gap-4">
        <div>
          <label className="block text-[10px] uppercase font-bold text-siemMuted mb-1.5">Search Query</label>
          <input 
            type="text" 
            placeholder="IP, description, detector..."
            value={localSearch}
            onChange={(e) => handleSearchChange(e.target.value)}
            className="w-full bg-slate-900 border border-siemBorder rounded p-2 text-xs text-gray-200 focus:outline-none"
          />
        </div>
        <div>
          <label className="block text-[10px] uppercase font-bold text-siemMuted mb-1.5">Detector</label>
          <select 
            value={localDet} 
            onChange={(e) => handleDetChange(e.target.value)}
            className="w-full bg-slate-900 border border-siemBorder rounded p-2 text-xs text-gray-200 focus:outline-none"
          >
            <option value="ALL">All Detectors</option>
            <option value="Hybrid Fusion">Hybrid Fusion</option>
            <option value="LSTM Autoencoder">LSTM Autoencoder</option>
            <option value="Isolation Forest">Isolation Forest</option>
            <option value="Suricata">Suricata</option>
            <option value="YARA">YARA</option>
            <option value="Snort">Snort</option>
          </select>
        </div>
        <div className="flex items-end">
          <button 
            onClick={() => { setLocalSearch(''); setLocalSev('ALL'); setLocalDet('ALL'); setCurrentPage(1); setExpIdx(null); }}
            className="w-full border border-siemBorder hover:bg-siemHover text-xs text-gray-300 py-2 rounded font-semibold transition"
          >
            Clear Filters
          </button>
        </div>
      </div>

      {/* Table & Severity Tabs Card */}
      <div className="bg-siemCard border border-siemBorder rounded p-5">
        
        {/* Severity Tabs */}
        <div className="flex border-b border-siemBorder mb-5 overflow-x-auto">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => {
            const count = alerts.filter(a => {
              const matchesSev = sev === 'ALL' || window.normalizeSeverity(a.severity).toUpperCase() === sev;
              const matchesDet = localDet === 'ALL' || a.detector === localDet;
              const matchesSearch = !localSearch || (
                a.detector.toLowerCase().includes(localSearch.toLowerCase()) || 
                a.source_ip.includes(localSearch) || 
                a.destination_ip.includes(localSearch) || 
                a.description.toLowerCase().includes(localSearch.toLowerCase())
              );
              return matchesSev && matchesDet && matchesSearch;
            }).length;
            
            return (
              <button
                key={sev}
                onClick={() => handleSevChange(sev)}
                className={`px-4 py-2.5 border-b-2 font-bold text-[11px] uppercase transition tracking-wider flex items-center gap-2 shrink-0 ${
                  localSev === sev
                    ? 'border-cyan-500 text-cyan-400'
                    : 'border-transparent text-siemMuted hover:text-gray-300 hover:border-slate-800'
                }`}
              >
                {sev === 'ALL' ? 'All Alerts' : sev}
                <span className={`px-1.5 py-0.5 rounded-full text-[9px] font-mono font-bold ${
                  localSev === sev ? 'bg-cyan-500/20 text-cyan-400' : 'bg-slate-900 text-slate-500'
                }`}>
                  {count}
                </span>
              </button>
            );
          })}
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse">
            <thead>
              <tr className="border-b border-siemBorder text-[10px] uppercase font-bold text-siemMuted tracking-wider">
                <th className="p-3 w-8"></th>
                <th className="p-3">Time</th>
                <th className="p-3">Severity</th>
                <th className="p-3">Detector</th>
                <th className="p-3">Source IP</th>
                <th className="p-3">Destination IP</th>
                <th className="p-3">Protocol</th>
                <th className="p-3">Risk</th>
                <th className="p-3">Reason</th>
              </tr>
            </thead>
            <tbody>
              {paginatedAlerts.length === 0 ? (
                <tr>
                  <td colSpan="9" className="text-center p-6 text-xs text-siemMuted">No alerts match search criteria.</td>
                </tr>
              ) : (
                paginatedAlerts.map((a, idx) => {
                  const globalIdx = startIndex + idx;
                  const isExpanded = expIdx === globalIdx;
                  const sev = window.normalizeSeverity(a.severity);
                  let sevColor = "text-yellow-500 bg-yellow-500/5 border border-yellow-500/20";
                  if (sev === "Critical") sevColor = "text-rose-500 bg-rose-500/5 border border-rose-500/20";
                  else if (sev === "High") sevColor = "text-orange-400 bg-orange-400/5 border border-orange-400/20";
                  else if (sev === "Low") sevColor = "text-blue-400 bg-blue-400/5 border border-blue-400/20";

                  return (
                    <React.Fragment key={globalIdx}>
                      <tr 
                        onClick={() => setExpIdx(isExpanded ? null : globalIdx)}
                        className={`border-b border-siemBorder text-xs hover:bg-siemHover transition cursor-pointer ${isExpanded ? 'bg-siemHover/50' : ''}`}
                      >
                        <td className="p-3 text-center">
                          <i className={`bi text-siemMuted text-2xs ${isExpanded ? 'bi-chevron-down' : 'bi-chevron-right'}`}></i>
                        </td>
                        <td className="p-3 font-mono text-[11px] text-siemMuted">{window.formatTime(a.timestamp)}</td>
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${sevColor}`}>{sev}</span>
                        </td>
                        <td className="p-3 font-semibold">{a.detector}</td>
                        <td className="p-3 font-mono text-sky-400">{a.source_ip}</td>
                        <td className="p-3 font-mono text-sky-400">{a.destination_ip}</td>
                        <td className="p-3 font-mono text-siemMuted">{a.protocol}</td>
                        <td className="p-3 font-mono font-bold text-orange-400">{a.risk_score}</td>
                        <td className="p-3 text-siemMuted max-w-xs truncate">{a.description}</td>
                      </tr>
                      {isExpanded && (
                        <tr className="bg-slate-950/70 border-b border-siemBorder">
                          <td colSpan="9" className="p-4">
                            <pre className="font-mono text-[11px] text-emerald-500 bg-black/60 border border-siemBorder p-4 rounded leading-relaxed overflow-x-auto">
                              {JSON.stringify({
                                event_id: `TF-EXPLORER-${a.detector.replace(/\s+/g, '')}-${globalIdx}`,
                                timestamp: a.timestamp,
                                severity: a.severity,
                                detector: a.detector,
                                source: a.source_ip,
                                destination: a.destination_ip,
                                protocol: a.protocol,
                                risk_score: a.risk_score,
                                description: a.description,
                                payload: a.payload
                              }, null, 2)}
                            </pre>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {/* Pagination Controls */}
        {totalPages > 1 && (
          <div className="flex justify-between items-center mt-5 text-[11px] text-siemMuted bg-slate-900/40 p-3 border border-siemBorder rounded-lg">
            <div>
              Showing <span className="font-semibold text-gray-200">{startIndex + 1}</span> to <span className="font-semibold text-gray-200">{Math.min(startIndex + itemsPerPage, filtered.length)}</span> of <span className="font-semibold text-gray-200">{filtered.length}</span> alerts
            </div>
            <div className="flex items-center gap-1">
              <button
                onClick={() => { setCurrentPage(1); setExpIdx(null); }}
                disabled={activePage === 1}
                className="px-2 py-1 rounded bg-slate-950 border border-siemBorder text-gray-300 hover:bg-siemHover disabled:opacity-40 disabled:hover:bg-slate-950 transition"
              >
                First
              </button>
              <button
                onClick={() => { setCurrentPage(prev => Math.max(1, prev - 1)); setExpIdx(null); }}
                disabled={activePage === 1}
                className="px-2 py-1 rounded bg-slate-950 border border-siemBorder text-gray-300 hover:bg-siemHover disabled:opacity-40 disabled:hover:bg-slate-950 transition"
              >
                Prev
              </button>
              
              {/* Sliding page indicators */}
              {Array.from({ length: totalPages }).map((_, i) => {
                const pageNum = i + 1;
                if (
                  pageNum === 1 || 
                  pageNum === totalPages || 
                  Math.abs(pageNum - activePage) <= 1
                ) {
                  return (
                    <button
                      key={pageNum}
                      onClick={() => { setCurrentPage(pageNum); setExpIdx(null); }}
                      className={`px-2.5 py-1 rounded font-mono font-semibold transition ${
                        activePage === pageNum
                          ? 'bg-cyan-500 text-slate-950 border border-cyan-400 font-bold'
                          : 'bg-slate-950 border border-siemBorder text-gray-300 hover:bg-siemHover'
                      }`}
                    >
                      {pageNum}
                    </button>
                  );
                }
                if (pageNum === 2 || pageNum === totalPages - 1) {
                  return <span key={pageNum} className="px-1 text-slate-600">...</span>;
                }
                return null;
              }).filter((val, i, self) => {
                if (val && val.type === 'span' && self[i - 1] && self[i - 1].type === 'span') return false;
                return true;
              })}

              <button
                onClick={() => { setCurrentPage(prev => Math.min(totalPages, prev + 1)); setExpIdx(null); }}
                disabled={activePage === totalPages}
                className="px-2 py-1 rounded bg-slate-950 border border-siemBorder text-gray-300 hover:bg-siemHover disabled:opacity-40 disabled:hover:bg-slate-950 transition"
              >
                Next
              </button>
              <button
                onClick={() => { setCurrentPage(totalPages); setExpIdx(null); }}
                disabled={activePage === totalPages}
                className="px-2 py-1 rounded bg-slate-950 border border-siemBorder text-gray-300 hover:bg-siemHover disabled:opacity-40 disabled:hover:bg-slate-950 transition"
              >
                Last
              </button>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

// Bind to window for global availability
window.RenderExplorerTab = RenderExplorerTab;
