#include "threatfusion/Evaluator.h"

#include "threatfusion/Csv.h"

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <vector>

namespace threatfusion {

static double ratio(int numerator, int denominator) {
    return denominator == 0 ? 0.0 : static_cast<double>(numerator) / denominator;
}

Metrics evaluateMetrics(const std::vector<Event>& events,
                        const std::map<std::string, Alert>& alerts,
                        int maliciousThreshold) {
    Metrics metrics;
    metrics.totalAlerts = static_cast<int>(alerts.size());
    std::map<std::string, bool> knownEventIds;
    for (const auto& event : events) {
        knownEventIds[event.id] = true;
    }
    for (const auto& entry : alerts) {
        if (knownEventIds.count(entry.first) == 0) {
            ++metrics.externalAlerts;
        }
    }

    for (const auto& event : events) {
        const auto label = toLower(event.label);
        if (label != "malicious" && label != "benign") {
            ++metrics.unlabeledEvents;
            continue;
        }

        ++metrics.evaluatedEvents;
        const bool actualMalicious = label == "malicious";
        const auto found = alerts.find(event.id);
        const bool predictedMalicious = found != alerts.end() && found->second.riskScore >= maliciousThreshold;

        if (actualMalicious && predictedMalicious) ++metrics.truePositive;
        else if (!actualMalicious && !predictedMalicious) ++metrics.trueNegative;
        else if (!actualMalicious && predictedMalicious) ++metrics.falsePositive;
        else if (actualMalicious && !predictedMalicious) ++metrics.falseNegative;
    }

    metrics.precision = ratio(metrics.truePositive, metrics.truePositive + metrics.falsePositive);
    metrics.recall = ratio(metrics.truePositive, metrics.truePositive + metrics.falseNegative);
    metrics.f1 = (metrics.precision + metrics.recall) == 0.0
        ? 0.0
        : 2.0 * metrics.precision * metrics.recall / (metrics.precision + metrics.recall);
    metrics.accuracy = ratio(metrics.truePositive + metrics.trueNegative,
                             metrics.truePositive + metrics.trueNegative + metrics.falsePositive + metrics.falseNegative);
    metrics.falsePositiveRate = ratio(metrics.falsePositive, metrics.falsePositive + metrics.trueNegative);

    std::vector<double> latencies;
    for (const auto& entry : alerts) {
        latencies.push_back(entry.second.latencyMs);
    }
    if (!latencies.empty()) {
        std::sort(latencies.begin(), latencies.end());
        double total = 0.0;
        for (const auto latency : latencies) {
            total += latency;
        }
        metrics.averageLatencyMs = total / static_cast<double>(latencies.size());
        const auto p95Index = static_cast<std::size_t>(std::ceil(0.95 * latencies.size())) - 1;
        metrics.p95LatencyMs = latencies[p95Index];
        metrics.maxLatencyMs = latencies.back();
    }
    return metrics;
}

std::string formatMetrics(const Metrics& metrics) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(3);
    out << "evaluated_events=" << metrics.evaluatedEvents << '\n';
    out << "unlabeled_events=" << metrics.unlabeledEvents << '\n';
    out << "total_alerts=" << metrics.totalAlerts << '\n';
    out << "external_alerts=" << metrics.externalAlerts << '\n';
    out << "TP=" << metrics.truePositive << '\n';
    out << "TN=" << metrics.trueNegative << '\n';
    out << "FP=" << metrics.falsePositive << '\n';
    out << "FN=" << metrics.falseNegative << '\n';
    out << "precision=" << metrics.precision << '\n';
    out << "recall=" << metrics.recall << '\n';
    out << "f1=" << metrics.f1 << '\n';
    out << "accuracy=" << metrics.accuracy << '\n';
    out << "false_positive_rate=" << metrics.falsePositiveRate << '\n';
    out << "avg_latency_ms=" << metrics.averageLatencyMs << '\n';
    out << "p95_latency_ms=" << metrics.p95LatencyMs << '\n';
    out << "max_latency_ms=" << metrics.maxLatencyMs << '\n';
    return out.str();
}

} // namespace threatfusion
