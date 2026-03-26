#pragma once

#include "threatfusion/Detection.h"
#include "threatfusion/Event.h"

#include <set>
#include <string>
#include <vector>

namespace threatfusion {

class BaselineDetector {
public:
    void train(const std::vector<Event>& events);
    std::vector<Detection> evaluate(const Event& event) const;
    bool empty() const { return peers_.empty(); }

private:
    std::set<std::string> peers_;
    std::set<std::string> flows_;
    std::set<std::string> protocolFunctions_;
    std::set<std::string> hourlyFlows_;
};

} // namespace threatfusion
