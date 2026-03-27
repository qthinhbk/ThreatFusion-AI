#pragma once

#include "threatfusion/Detection.h"
#include "threatfusion/Event.h"

#include <vector>

namespace threatfusion {

class RiskScorer {
public:
    Alert score(const Event& event, const std::vector<Detection>& detections) const;
};

int severityWeight(const std::string& severity);
std::string highestSeverity(const std::vector<Detection>& detections);

} // namespace threatfusion
