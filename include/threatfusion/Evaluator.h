#pragma once

#include "threatfusion/Detection.h"
#include "threatfusion/Event.h"

#include <map>
#include <string>
#include <vector>

namespace threatfusion {

struct Metrics {
    int evaluatedEvents = 0;
    int unlabeledEvents = 0;
    int totalAlerts = 0;
    int externalAlerts = 0;
    int truePositive = 0;
    int trueNegative = 0;
    int falsePositive = 0;
    int falseNegative = 0;
    double precision = 0.0;
    double recall = 0.0;
    double f1 = 0.0;
    double accuracy = 0.0;
    double falsePositiveRate = 0.0;
    double averageLatencyMs = 0.0;
    double p95LatencyMs = 0.0;
    double maxLatencyMs = 0.0;
};

Metrics evaluateMetrics(const std::vector<Event>& events,
                        const std::map<std::string, Alert>& alerts,
                        int maliciousThreshold);

std::string formatMetrics(const Metrics& metrics);

} // namespace threatfusion
