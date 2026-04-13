#include "threatfusion/BaselineDetector.h"
#include "threatfusion/BehaviorDetector.h"
#include "threatfusion/Csv.h"
#include "threatfusion/DataIngestion.h"
#include "threatfusion/Evaluator.h"
#include "threatfusion/ExternalScanner.h"
#include "threatfusion/IncidentAggregator.h"
#include "threatfusion/IsolationForestDetector.h"
#include "threatfusion/LSTMDetector.h"
#include "threatfusion/RiskScorer.h"
#include "threatfusion/SocketReceiver.h"
#include "threatfusion/ThreatIntel.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <stdexcept>
#include <vector>

using namespace threatfusion;

struct Options {
  std::string mode = "batch";
  int port = 8080;
  std::string lstmPath;
  std::string eventsPath = "data/sample_ot_events.csv";
  std::string inputFormat = "csv";
  std::string tsharkPath = "tshark";
  std::string baselinePath;
  std::string baselineFormat = "csv";
  std::string iocsPath = "data/iocs.csv";
  std::string rulesPath = "data/behavior_rules.csv";
  std::string yaraPath;
  std::string yaraRulesPath;
  std::string snortPath;
  std::string snortConfigPath;
  std::string suricataPath;
  std::string suricataRulesPath;
  std::string suricataLogDir = "out/suricata";
  std::string alertsPath = "out/alerts.csv";
  std::string incidentsPath = "out/incidents.csv";
  std::string metricsPath = "out/metrics.txt";
  int threshold = 60;
};

static void printUsage() {
  std::cout
      << "ThreatFusion AI - OT/ICS threat detection prototype\n"
      << "Usage: threatfusion [--mode batch|stream] [--port port] [--lstm "
         "path]\n"
      << "                    [--events path] [--format csv|jsonl|pcap] "
         "[--tshark path]\n"
      << "                    [--baseline path] [--baseline-format csv|jsonl]\n"
      << "                    [--iocs path] [--rules path] [--yara path "
         "--yara-rules path]\n"
      << "                    [--suricata path --suricata-rules path]\n"
      << "                    [--snort path --snort-config path]\n"
      << "                    [--alerts path] [--incidents path]\n"
      << "                    [--metrics path] [--threshold 60]\n";
}

static Options parseArgs(int argc, char **argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    auto requireValue = [&](const std::string &name) -> std::string {
      if (i + 1 >= argc) {
        throw std::runtime_error("Missing value for " + name);
      }
      return argv[++i];
    };

    if (arg == "--mode")
      options.mode = requireValue(arg);
    else if (arg == "--port")
      options.port = std::stoi(requireValue(arg));
    else if (arg == "--lstm")
      options.lstmPath = requireValue(arg);
    else if (arg == "--events")
      options.eventsPath = requireValue(arg);
    else if (arg == "--format")
      options.inputFormat = requireValue(arg);
    else if (arg == "--tshark")
      options.tsharkPath = requireValue(arg);
    else if (arg == "--baseline")
      options.baselinePath = requireValue(arg);
    else if (arg == "--baseline-format")
      options.baselineFormat = requireValue(arg);
    else if (arg == "--iocs")
      options.iocsPath = requireValue(arg);
    else if (arg == "--rules")
      options.rulesPath = requireValue(arg);
    else if (arg == "--yara")
      options.yaraPath = requireValue(arg);
    else if (arg == "--yara-rules")
      options.yaraRulesPath = requireValue(arg);
    else if (arg == "--snort")
      options.snortPath = requireValue(arg);
    else if (arg == "--snort-config")
      options.snortConfigPath = requireValue(arg);
    else if (arg == "--suricata")
      options.suricataPath = requireValue(arg);
    else if (arg == "--suricata-rules")
      options.suricataRulesPath = requireValue(arg);
    else if (arg == "--suricata-logdir")
      options.suricataLogDir = requireValue(arg);
    else if (arg == "--alerts")
      options.alertsPath = requireValue(arg);
    else if (arg == "--incidents")
      options.incidentsPath = requireValue(arg);
    else if (arg == "--metrics")
      options.metricsPath = requireValue(arg);
    else if (arg == "--threshold")
      options.threshold = std::stoi(requireValue(arg));
    else if (arg == "--help" || arg == "-h") {
      printUsage();
      std::exit(0);
    } else {
      throw std::runtime_error("Unknown argument: " + arg);
    }
  }
  return options;
}

int main(int argc, char **argv) {
  try {
    const auto options = parseArgs(argc, argv);

    ThreatIntel threatIntel;
    threatIntel.loadIocs(options.iocsPath);

    BehaviorDetector detector;
    detector.loadRules(options.rulesPath);

    BaselineDetector baselineDetector;
    IsolationForestDetector isolationForestDetector;
    if (!options.baselinePath.empty()) {
      IngestionOptions baselineOptions;
      baselineOptions.format = options.baselineFormat;
      baselineOptions.tsharkPath = options.tsharkPath;
      const auto baselineEvents =
          loadEvents(options.baselinePath, baselineOptions);
      baselineDetector.train(baselineEvents);
      isolationForestDetector.train(baselineEvents, 100);
    }

    LSTMDetector lstmDetector;
    if (!options.lstmPath.empty()) {
      lstmDetector.loadModel(options.lstmPath);
    }

    ExternalScanner externalScanner;
    if (!options.yaraPath.empty() && !options.yaraRulesPath.empty()) {
      externalScanner.setYara(options.yaraPath, options.yaraRulesPath);
    }
    if (!options.snortPath.empty() && !options.snortConfigPath.empty() &&
        toLower(options.inputFormat) == "pcap") {
      externalScanner.setSnort(options.snortPath, options.snortConfigPath,
                               options.eventsPath);
    }
    if (!options.suricataPath.empty() && !options.suricataRulesPath.empty() &&
        toLower(options.inputFormat) == "pcap") {
      externalScanner.setSuricata(options.suricataPath,
                                  options.suricataRulesPath, options.eventsPath,
                                  options.suricataLogDir);
    }

    if (toLower(options.mode) == "stream") {
      SocketReceiver receiver;
      RiskScorer scorer;
      auto callback = [&](const Event &event) {
        const auto detectionStart = std::chrono::steady_clock::now();
        auto detections = threatIntel.correlate(event);
        auto behavioral = detector.evaluate(event);
        detections.insert(detections.end(), behavioral.begin(),
                          behavioral.end());
        auto baseline = baselineDetector.evaluate(event);
        detections.insert(detections.end(), baseline.begin(), baseline.end());
        auto isolationForest = isolationForestDetector.evaluate(event);
        detections.insert(detections.end(), isolationForest.begin(),
                          isolationForest.end());
        auto lstm = lstmDetector.evaluate(event);
        detections.insert(detections.end(), lstm.begin(), lstm.end());
        auto external = externalScanner.evaluate(event);
        detections.insert(detections.end(), external.begin(), external.end());

        if (detections.empty()) {
          return;
        }

        auto alert = scorer.score(event, detections);
        const auto detectionEnd = std::chrono::steady_clock::now();
        alert.latencyMs = std::chrono::duration<double, std::milli>(
                              detectionEnd - detectionStart)
                              .count();

        std::cout << "[ALERT] Event: " << alert.eventId
                  << " | IP: " << alert.srcIp << " -> " << alert.dstIp
                  << " | Protocol: " << alert.protocol
                  << " | Risk Score: " << alert.riskScore
                  << " | Verdict: " << alert.verdict
                  << " | Reasons: " << alert.reasons << "\n";

        // Append alert to stream log file
        ensureParentDirectory("out/alerts_stream.csv");
        bool fileExists = std::ifstream("out/alerts_stream.csv").good();
        std::ofstream outStream("out/alerts_stream.csv", std::ios::app);
        if (outStream.is_open()) {
          if (!fileExists) {
            outStream
                << "incident_id,event_id,timestamp,src_ip,dst_ip,asset_role,"
                   "protocol,"
                << "classification,top_severity,asset_criticality,threat_"
                   "severity,"
                << "confidence_score,risk_score,latency_ms,verdict,reasons\n";
          }
          outStream << alert.incidentId << "," << alert.eventId << ","
                    << alert.timestamp << "," << alert.srcIp << ","
                    << alert.dstIp << "," << alert.assetRole << ","
                    << alert.protocol << "," << alert.classification << ","
                    << alert.topSeverity << "," << alert.assetCriticality << ","
                    << alert.threatSeverity << "," << alert.confidenceScore
                    << "," << alert.riskScore << "," << alert.latencyMs << ","
                    << "\"" << alert.verdict << "\",\"" << alert.reasons
                    << "\"\n";
        }
      };

      if (!receiver.start(options.port, callback)) {
        std::cerr << "Failed to start socket receiver on port " << options.port
                  << "\n";
        return 1;
      }

      std::cout << "ThreatFusion Engine running in STREAMING mode on port "
                << options.port << "\n";
      std::cout << "Press Enter to stop the engine...\n";
      std::cin.get();
      receiver.stop();
      return 0;
    }

    IngestionOptions ingestionOptions;
    ingestionOptions.format = options.inputFormat;
    ingestionOptions.tsharkPath = options.tsharkPath;
    const auto events = loadEvents(options.eventsPath, ingestionOptions);

    RiskScorer scorer;
    std::vector<Alert> alerts;

    for (const auto &event : events) {
      const auto detectionStart = std::chrono::steady_clock::now();
      auto detections = threatIntel.correlate(event);
      auto behavioral = detector.evaluate(event);
      detections.insert(detections.end(), behavioral.begin(), behavioral.end());
      auto baseline = baselineDetector.evaluate(event);
      detections.insert(detections.end(), baseline.begin(), baseline.end());
      auto isolationForest = isolationForestDetector.evaluate(event);
      detections.insert(detections.end(), isolationForest.begin(),
                        isolationForest.end());
      auto lstm = lstmDetector.evaluate(event);
      detections.insert(detections.end(), lstm.begin(), lstm.end());
      auto external = externalScanner.evaluate(event);
      detections.insert(detections.end(), external.begin(), external.end());

      if (detections.empty()) {
        continue;
      }

      auto alert = scorer.score(event, detections);
      const auto detectionEnd = std::chrono::steady_clock::now();
      alert.latencyMs = std::chrono::duration<double, std::milli>(
                            detectionEnd - detectionStart)
                            .count();
      alerts.push_back(alert);
    }

    for (const auto &detection : externalScanner.evaluatePcap()) {
      Event event;
      event.id = detection.eventId;
      event.timestamp =
          detection.timestamp.empty() ? "pcap" : detection.timestamp;
      event.srcIp = detection.srcIp;
      event.dstIp = detection.dstIp;
      event.assetRole =
          detection.assetRole.empty() ? "network" : detection.assetRole;
      event.protocol = detection.protocol.empty() ? "pcap" : detection.protocol;
      auto alert = scorer.score(event, {detection});
      alert.latencyMs = 0.0;
      alerts.push_back(alert);
    }

    const auto incidents = aggregateIncidents(alerts);

    std::map<std::string, Alert> alertsByEventId;
    std::vector<std::vector<std::string>> alertRows;
    for (const auto &alert : alerts) {
      alertsByEventId[alert.eventId] = alert;
      alertRows.push_back(
          {alert.incidentId, alert.eventId, alert.timestamp, alert.srcIp,
           alert.dstIp, alert.assetRole, alert.protocol, alert.classification,
           alert.topSeverity, std::to_string(alert.assetCriticality),
           std::to_string(alert.threatSeverity),
           std::to_string(alert.confidenceScore),
           std::to_string(alert.riskScore), std::to_string(alert.latencyMs),
           alert.verdict, alert.reasons});
    }

    writeCsv(options.alertsPath,
             {"incident_id", "event_id", "timestamp", "src_ip", "dst_ip",
              "asset_role", "protocol", "classification", "top_severity",
              "asset_criticality", "threat_severity", "confidence_score",
              "risk_score", "latency_ms", "verdict", "reasons"},
             alertRows);

    std::vector<std::vector<std::string>> incidentRows;
    for (const auto &incident : incidents) {
      incidentRows.push_back(
          {incident.id, incident.firstSeen, incident.lastSeen,
           incident.classification, incident.topSeverity,
           std::to_string(incident.maxRiskScore),
           std::to_string(incident.alertCount), incident.srcIp, incident.dstIp,
           incident.affectedAssets, incident.eventIds});
    }
    writeCsv(options.incidentsPath,
             {"incident_id", "first_seen", "last_seen", "classification",
              "top_severity", "max_risk_score", "alert_count", "src_ip",
              "dst_ip", "affected_assets", "event_ids"},
             incidentRows);

    const auto metrics =
        evaluateMetrics(events, alertsByEventId, options.threshold);
    const auto metricsText = formatMetrics(metrics);
    ensureParentDirectory(options.metricsPath);
    std::ofstream metricsFile(options.metricsPath);
    metricsFile << metricsText;

    std::cout << "events=" << events.size() << '\n';
    std::cout << "alerts=" << alertRows.size() << '\n';
    std::cout << "incidents=" << incidents.size() << '\n';
    std::cout << metricsText;
    std::cout << "alerts_path=" << options.alertsPath << '\n';
    std::cout << "incidents_path=" << options.incidentsPath << '\n';
    std::cout << "metrics_path=" << options.metricsPath << '\n';
    return 0;
  } catch (const std::exception &ex) {
    std::cerr << "error: " << ex.what() << '\n';
    return 1;
  }
}
