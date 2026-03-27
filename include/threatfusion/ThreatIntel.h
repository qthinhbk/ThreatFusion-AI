#pragma once

#include "threatfusion/Detection.h"
#include "threatfusion/Event.h"

#include <string>
#include <vector>

namespace threatfusion {

struct Ioc {
    std::string type;
    std::string value;
    std::string severity;
    std::string malwareFamily;
    std::string description;
};

class ThreatIntel {
public:
    bool loadIocs(const std::string& path);
    std::vector<Detection> correlate(const Event& event) const;
    const std::vector<Ioc>& iocs() const { return iocs_; }

private:
    std::vector<Ioc> iocs_;
};

} // namespace threatfusion
