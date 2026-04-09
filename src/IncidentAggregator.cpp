#include "threatfusion/IncidentAggregator.h"

#include "threatfusion/Csv.h"
#include "threatfusion/RiskScorer.h"

#include <algorithm>
#include <map>
#include <set>
#include <sstream>

namespace threatfusion {

static std::string joinSet(const std::set<std::string>& values) {
    std::ostringstream out;
    bool first = true;
    for (const auto& value : values) {
        if (!first) {
            out << '|';
        }
        out << value;
        first = false;
    }
    return out.str();
}

std::vector<Incident> aggregateIncidents(std::vector<Alert>& alerts) {
    struct Builder {
        Incident incident;
        std::set<std::string> assets;
        std::set<std::string> eventIds;
    };

    std::map<std::string, Builder> grouped;
    int nextIncidentId = 1;

    for (auto& alert : alerts) {
        const auto key = alert.srcIp + "|" + alert.dstIp + "|" + alert.classification;
        auto& builder = grouped[key];
        if (builder.incident.id.empty()) {
            builder.incident.id = "INC-" + std::to_string(nextIncidentId++);
            builder.incident.firstSeen = alert.timestamp;
            builder.incident.classification = alert.classification;
            builder.incident.srcIp = alert.srcIp;
            builder.incident.dstIp = alert.dstIp;
        }

        alert.incidentId = builder.incident.id;
        builder.incident.lastSeen = alert.timestamp;
        builder.incident.alertCount += 1;
        builder.incident.maxRiskScore = std::max(builder.incident.maxRiskScore, alert.riskScore);
        if (severityWeight(alert.topSeverity) > severityWeight(builder.incident.topSeverity)) {
            builder.incident.topSeverity = alert.topSeverity;
        }
        builder.assets.insert(alert.assetRole);
        builder.eventIds.insert(alert.eventId);
    }

    std::vector<Incident> incidents;
    for (auto& entry : grouped) {
        entry.second.incident.affectedAssets = joinSet(entry.second.assets);
        entry.second.incident.eventIds = joinSet(entry.second.eventIds);
        incidents.push_back(entry.second.incident);
    }
    return incidents;
}

} // namespace threatfusion
