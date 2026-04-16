// Static baseline data and constants
window.defaultAlerts = [
  { timestamp: "2026-06-11T01:10:00Z", severity: "Critical", detector: "Hybrid Fusion", source_ip: "10.0.0.1", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 98, description: "Correlated Modbus anomalous command write & high LSTM error (F1 optimal weight)", payload: { fc: 6, register: 1024, val: 85, lstm_loss: 0.009044, threshold: 0.0055 } },
  { timestamp: "2026-06-11T01:05:30Z", severity: "High", detector: "LSTM Autoencoder", source_ip: "10.0.0.1", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 82, description: "Sequential reconstruction deviation on pipeline setpoints", payload: { fc: 16, register: 2048, length: 4, lstm_loss: 0.007621, threshold: 0.0055 } },
  { timestamp: "2026-06-11T01:02:12Z", severity: "High", detector: "Isolation Forest", source_ip: "10.0.0.1", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 80, description: "Outlier data payload structure detected on SolenoidState write", payload: { fc: 5, address: 512, state: 1, if_score: 0.612, threshold: 0.55 } },
  { timestamp: "2026-06-11T00:58:00Z", severity: "Critical", detector: "Suricata", source_ip: "10.0.0.10", destination_ip: "10.0.0.2", protocol: "TCP", risk_score: 95, description: "SID 2038411 - Modbus RTU flooding signature triggered", payload: { signature: "ET PRO SCADA Modbus Flooding", sid: 2038411, count: 1450 } },
  { timestamp: "2026-06-11T00:52:00Z", severity: "Medium", detector: "YARA", source_ip: "10.0.0.11", destination_ip: "10.0.0.1", protocol: "SMB", risk_score: 65, description: "Stuxnet DLL Hooker binary offset matched on HMI workstation", payload: { file_path: "C:\\Windows\\System32\\dbgsrv.dll", match: "stuxnet_dll_hooker" } },
  { timestamp: "2026-06-11T00:40:00Z", severity: "Low", detector: "Snort", source_ip: "10.0.0.5", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 35, description: "Modbus read coils unauthorized station query", payload: { fc: 1, start_address: 0, count: 100 } },
  { timestamp: "2026-06-11T00:30:00Z", severity: "Medium", detector: "LSTM Autoencoder", source_ip: "10.0.0.1", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 68, description: "Off-cycle command sequences deviate from historical normal baseline", payload: { fc: 3, register: 102, lstm_loss: 0.006112, threshold: 0.0055 } }
];

window.defaultIncidents = [
  { incident_id: "INC-2026-01", severity: "Critical", event_count: 5, risk_score: 98, status: "Open", first_seen: "2026-06-11T00:58:00Z", last_seen: "2026-06-11T01:10:00Z" },
  { incident_id: "INC-2026-02", severity: "High", event_count: 2, risk_score: 82, status: "Investigating", first_seen: "2026-06-11T00:52:00Z", last_seen: "2026-06-11T01:05:30Z" },
  { incident_id: "INC-2026-03", severity: "Low", event_count: 1, risk_score: 35, status: "Resolved", first_seen: "2026-06-11T00:40:00Z", last_seen: "2026-06-11T00:40:00Z" }
];

window.simAlertPool = [
  { severity: "Critical", detector: "Hybrid Fusion", source_ip: "10.0.0.1", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 97, description: "Modbus command injection correlation: w_IF=0.7 + w_LSTM=0.3", payload: { fc: 6, register: 1024, val: 99, lstm_loss: 0.0125, if_score: 0.69 } },
  { severity: "High", detector: "LSTM Autoencoder", source_ip: "10.0.0.1", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 88, description: "Reconstruction error threshold exceedance on PipelinePSI (Tuned limit)", payload: { fc: 3, register: 4001, psi_val: 145.2, lstm_loss: 0.00892, threshold: 0.0055 } },
  { severity: "Critical", detector: "Suricata", source_ip: "10.0.0.15", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 99, description: "Industroyer APDU malicious packet signature match", payload: { signature: "Industroyer Modbus Master Hijack", rule_id: 100052, severity: "Critical" } },
  { severity: "High", detector: "YARA", source_ip: "10.0.0.3", destination_ip: "10.0.0.5", protocol: "HTTP", risk_score: 85, description: "PipeDream CODESYS runtime exploit indicator matched", payload: { process_id: 4122, indicators: ["pipedream_codesys_hook", "exploit_rce"] } },
  { severity: "Medium", detector: "Isolation Forest", source_ip: "10.0.0.1", destination_ip: "10.0.0.2", protocol: "MODBUS", risk_score: 60, description: "Anomaly payload scoring - unusual PumpState register transition", payload: { fc: 5, address: 200, state: 0, if_score: 0.585 } },
  { severity: "Critical", detector: "Suricata", source_ip: "10.0.0.10", destination_ip: "10.0.0.2", protocol: "TCP", risk_score: 95, description: "SID 2038411 - Modbus RTU flooding signature triggered", payload: { signature: "ET PRO SCADA Modbus Flooding", sid: 2038411, count: 1800 } },
  { severity: "High", detector: "YARA", source_ip: "10.0.0.11", destination_ip: "10.0.0.1", protocol: "SMB", risk_score: 82, description: "WannaCry Ransomware SMB propagation attempt blocked", payload: { file_path: "C:\\Windows\\System32\\srv2.sys", match: "wannacry_ms17_010" } }
];

window.staticRules = [
  {
    id: "RULE-YARA-01",
    name: "stuxnet_dll_hooker",
    type: "YARA Signature",
    category: "Malware Indicators",
    status: "Loaded",
    description: "Detects DLL injection patterns used by Stuxnet malware in HMI",
    syntax: `rule stuxnet_dll_hooker {\n    meta:\n        description = "Detects DLL injection patterns used by Stuxnet malware in HMI"\n    strings:\n        $hex_offset = { 8B FF 55 8B EC 83 EC 10 53 56 57 }\n        $dll_name = "dbgsrv.dll" nocase\n    condition:\n        all of them\n}`
  },
  {
    id: "RULE-YARA-02",
    name: "industroyer_modbus_hijack",
    type: "YARA Signature",
    category: "Malware Indicators",
    status: "Loaded",
    description: "Detects Industroyer (CrashOverride) Modbus parser strings",
    syntax: `rule industroyer_modbus_hijack {\n    meta:\n        description = "Detects Industroyer Modbus command tool patterns"\n    strings:\n        $crash_str = "CrashOverride" nocase\n        $mb_cmd = "modbus_write_reg"\n    condition:\n        any of them\n}`
  },
  {
    id: "RULE-SURICATA-01",
    name: "modbus_flooding_sig",
    type: "Suricata Signature",
    category: "Network Anomaly",
    status: "Active",
    description: "Detects excessive Modbus commands over a short period from single source",
    syntax: `alert tcp any any -> any 502 (msg:"ET PRO SCADA Modbus Flooding"; flow:established,to_server; content:"|00 00 00 00 00|"; threshold:type threshold, track by_src, count 1000, seconds 2; sid:2038411; rev:1;)`
  },
  {
    id: "RULE-SNORT-01",
    name: "codesys_runtime_exploit",
    type: "Snort Signature",
    category: "Exploit Indicators",
    status: "Active",
    description: "Detects remote code execution attempts in CODESYS runtimes",
    syntax: `alert tcp any any -> any 1240 (msg:"CODESYS Runtime Exploit Attempt"; content:"|3c 78 6d 6c|"; sid:500021;)`
  },
  {
    id: "RULE-LSTM-01",
    name: "lstm_reconstruction_baseline",
    type: "Machine Learning",
    category: "Reconstruction Error",
    status: "Active",
    description: "Multi-layered LSTM autoencoder model trained on normal Modbus RTU payload sequences",
    syntax: `Model Architecture:\n  - Input layer: 12 features (sequential setpoints)\n  - LSTM Encoder: 64 hidden units, Dropout=0.2\n  - LSTM Decoder: 64 hidden units, Dropout=0.2\n  - Output Layer: 12 features (reconstruction)\n  - Trained Threshold Limit: 0.0055 (MSE loss)`
  },
  {
    id: "RULE-IF-01",
    name: "isolation_forest_setpoint_outlier",
    type: "Machine Learning",
    category: "Outlier Scoring",
    status: "Active",
    description: "Isolation Forest model detecting spatial payload value outliers on Modbus registers",
    syntax: `Model Configuration:\n  - Estimators: 100 trees\n  - Contamination parameter: 0.03\n  - Trained Threshold Limit: 0.55 (anomaly score)`
  }
];
