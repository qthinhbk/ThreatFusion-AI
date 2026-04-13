#include "threatfusion/BehaviorDetector.h"
#include "threatfusion/Csv.h"
#include "threatfusion/LSTMDetector.h"
#include "threatfusion/RiskScorer.h"
#include "threatfusion/SocketReceiver.h"
#include "threatfusion/ThreatIntel.h"

#include <cassert>
#include <cstdio>

using namespace threatfusion;

int main() {
  const auto row = parseCsvLine("a,\"b,c\",\"d\"\"e\"");
  assert(row.size() == 3);
  assert(row[1] == "b,c");
  assert(row[2] == "d\"e");

  const auto rulesPath = "test_rules.csv";
  writeCsv(rulesPath,
           {"id", "name", "severity", "tactic", "conditions", "description"},
           {{"R1", "Write to PLC", "high", "Impact",
             "protocol=modbus;function_code in 5|6|15|16;asset_role=plc",
             "write command"}});

  BehaviorDetector detector;
  assert(detector.loadRules(rulesPath));

  Event event;
  event.id = "E1";
  event.protocol = "modbus";
  event.functionCode = 16;
  event.assetRole = "plc";

  const auto detections = detector.evaluate(event);
  assert(detections.size() == 1);
  assert(detections[0].indicator == "R1");

  RiskScorer scorer;
  const auto alert = scorer.score(event, detections);
  assert(alert.riskScore >= 60);
  assert(alert.verdict == "critical" || alert.verdict == "malicious");

  std::remove(rulesPath);

  // Test LSTMDetector
  {
    LSTMDetector lstm;
    // Verify loading simulated fallback mode
    assert(lstm.loadModel("simulated"));

    // Push 10 events to satisfy sliding window (W=10)
    std::vector<Detection> lstmDetections;
    for (int i = 0; i < 10; ++i) {
      Event ev;
      ev.srcIp = "192.168.1.100";
      ev.dstIp = "192.168.1.11";
      ev.protocol = "modbus";
      ev.functionCode = 3;
      ev.assetRole = "plc";
      ev.bytes = 100 + i * 10;
      ev.timestamp = "2015-12-22T16:00:00Z";

      lstmDetections = lstm.evaluate(ev);
    }
    printf("[TEST] LSTMDetector evaluated successfully.\n");
  }

  // Test SocketReceiver
  {
    SocketReceiver receiver;
    auto dummyCallback = [](const Event &event) {};
    assert(receiver.start(8089, dummyCallback));
    receiver.stop();
    printf("[TEST] SocketReceiver started and stopped successfully.\n");
  }

  printf("[TEST] All ThreatFusion-AI tests passed successfully!\n");
  return 0;
}
