#pragma once

#include "threatfusion/Detection.h"
#include "threatfusion/Event.h"

#include <string>
#include <vector>

namespace threatfusion {

struct RuleCondition {
    std::string field;
    std::string op;
    std::string value;
};

struct BehaviorRule {
    std::string id;
    std::string name;
    std::string severity;
    std::string tactic;
    std::vector<RuleCondition> conditions;
    std::string description;
};

class BehaviorDetector {
public:
    bool loadRules(const std::string& path);
    std::vector<Detection> evaluate(const Event& event) const;
    const std::vector<BehaviorRule>& rules() const { return rules_; }

private:
    std::vector<BehaviorRule> rules_;
};

} // namespace threatfusion
