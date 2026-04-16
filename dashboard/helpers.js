// Global Helper functions
window.formatTime = function(isoStr) {
  if (!isoStr) return 'N/A';
  const d = new Date(isoStr);
  if (isNaN(d.getTime())) return isoStr;
  return d.toISOString().replace('T', ' ').substring(0, 19);
};

window.normalizeSeverity = function(sev) {
  if (!sev) return 'Medium';
  const s = sev.toUpperCase().trim();
  if (s === 'CRITICAL' || s === 'MALICIOUS') return 'Critical';
  if (s === 'HIGH') return 'High';
  if (s === 'MEDIUM' || s === 'WARNING') return 'Medium';
  if (s === 'LOW' || s === 'BENIGN') return 'Low';
  return 'Medium';
};

window.extractDetector = function(a) {
  if (a.detector) return a.detector;
  const reasonsStr = String(a.reasons || a.description || '').toLowerCase();
  if (reasonsStr.includes('isolation_forest')) {
    return 'Isolation Forest';
  }
  if (reasonsStr.includes('lstm')) {
    return 'LSTM Autoencoder';
  }
  if (reasonsStr.includes('yara')) {
    return 'YARA';
  }
  if (reasonsStr.includes('snort')) {
    return 'Snort';
  }
  if (reasonsStr.includes('suricata')) {
    return 'Suricata';
  }
  if (reasonsStr.includes('hybrid')) {
    return 'Hybrid Fusion';
  }
  if (reasonsStr.includes('ai_baseline')) {
    return 'AI Baseline';
  }
  return a.classification || 'Anomaly Detection';
};
