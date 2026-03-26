#include "threatfusion/BaselineDetector.h"

#include "threatfusion/Csv.h"

namespace threatfusion {

static std::string hourBucket(const std::string& timestamp) {
    if (timestamp.size() >= 13) {
        return timestamp.substr(11, 2);
    }
    return "unknown";
}

static std::string peerKey(const Event& event) {
    return event.srcIp + "->" + event.dstIp;
}

static std::string flowKey(const Event& event) {
    return peerKey(event) + "|" + toLower(event.protocol);
}

static std::string protocolFunctionKey(const Event& event) {
    return toLower(event.protocol) + "|" + std::to_string(event.functionCode) + "|" + toLower(event.assetRole);
}

static std::string hourlyFlowKey(const Event& event) {
    return flowKey(event) + "|" + hourBucket(event.timestamp);
}

void BaselineDetector::train(const std::vector<Event>& events) {
    peers_.clear();
    flows_.clear();
    protocolFunctions_.clear();
    hourlyFlows_.clear();

    for (const auto& event : events) {
        if (toLower(event.label) == "malicious") {
            continue;
        }
        peers_.insert(peerKey(event));
        flows_.insert(flowKey(event));
        protocolFunctions_.insert(protocolFunctionKey(event));
        hourlyFlows_.insert(hourlyFlowKey(event));
    }
}

std::vector<Detection> BaselineDetector::evaluate(const Event& event) const {
    std::vector<Detection> detections;
    if (empty()) {
        return detections;
    }

    if (peers_.count(peerKey(event)) == 0) {
        detections.push_back({
            event.id,
            "ai_baseline",
            "new_peer:" + peerKey(event),
            "high",
            "Anomaly Detection",
            "Source/destination pair was not observed in the trained OT baseline.",
            0.72
        });
    }

    if (flows_.count(flowKey(event)) == 0) {
        detections.push_back({
            event.id,
            "ai_baseline",
            "new_protocol_flow:" + flowKey(event),
            "high",
            "Anomaly Detection",
            "Protocol flow was not observed in the trained OT baseline.",
            0.74
        });
    }

    if (protocolFunctions_.count(protocolFunctionKey(event)) == 0) {
        detections.push_back({
            event.id,
            "ai_baseline",
            "new_function:" + protocolFunctionKey(event),
            "medium",
            "Anomaly Detection",
            "Industrial protocol function/asset combination deviates from baseline.",
            0.68
        });
    }

    if (hourlyFlows_.count(hourlyFlowKey(event)) == 0) {
        detections.push_back({
            event.id,
            "ai_baseline",
            "off_cycle:" + hourlyFlowKey(event),
            "medium",
            "Anomaly Detection",
            "Flow appears outside the learned hourly OT communication cycle.",
            0.62
        });
    }

    return detections;
}

} // namespace threatfusion
