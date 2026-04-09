#pragma once

#include "threatfusion/Detection.h"

#include <string>
#include <vector>

namespace threatfusion {

struct Incident {
    std::string id;
    std::string firstSeen;
    std::string lastSeen;
    std::string classification;
    std::string topSeverity;
    int maxRiskScore = 0;
    int alertCount = 0;
    std::string srcIp;
    std::string dstIp;
    std::string affectedAssets;
    std::string eventIds;
};

std::vector<Incident> aggregateIncidents(std::vector<Alert>& alerts);

} // namespace threatfusion
