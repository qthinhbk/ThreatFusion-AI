#include "threatfusion/BehaviorDetector.h"

#include "threatfusion/Csv.h"

#include <cstdlib>
#include <sstream>

namespace threatfusion {

static std::string fieldValue(const Event& event, const std::string& field) {
    const auto key = toLower(field);
    if (key == "id") return event.id;
    if (key == "timestamp") return event.timestamp;
    if (key == "src_ip") return event.srcIp;
    if (key == "dst_ip") return event.dstIp;
    if (key == "protocol") return event.protocol;
    if (key == "function_code") return std::to_string(event.functionCode);
    if (key == "asset_role") return event.assetRole;
    if (key == "payload_hash") return event.payloadHash;
    if (key == "bytes") return std::to_string(event.bytes);
    if (key == "action") return event.action;
    if (key == "label") return event.label;
    return "";
}

static bool numericCompare(const std::string& left, const std::string& op, const std::string& right) {
    const auto l = std::strtod(left.c_str(), nullptr);
    const auto r = std::strtod(right.c_str(), nullptr);
    if (op == ">") return l > r;
    if (op == ">=") return l >= r;
    if (op == "<") return l < r;
    if (op == "<=") return l <= r;
    return false;
}

static bool matchesCondition(const Event& event, const RuleCondition& condition) {
    const auto actual = toLower(fieldValue(event, condition.field));
    const auto expected = toLower(condition.value);
    const auto op = toLower(condition.op);

    if (op == "=" || op == "==") return actual == expected;
    if (op == "!=") return actual != expected;
    if (op == "contains") return actual.find(expected) != std::string::npos;
    if (op == "in") {
        for (const auto& item : split(expected, '|')) {
            if (actual == item) {
                return true;
            }
        }
        return false;
    }
    if (op == ">" || op == ">=" || op == "<" || op == "<=") {
        return numericCompare(actual, op, expected);
    }
    return false;
}

static RuleCondition parseCondition(const std::string& raw) {
    const std::vector<std::string> ops = {">=", "<=", "!=", " contains ", " in ", "==", "=", ">", "<"};
    for (const auto& op : ops) {
        const auto pos = raw.find(op);
        if (pos != std::string::npos) {
            RuleCondition condition;
            condition.field = trim(raw.substr(0, pos));
            condition.op = trim(op);
            condition.value = trim(raw.substr(pos + op.size()));
            return condition;
        }
    }
    return {};
}

bool BehaviorDetector::loadRules(const std::string& path) {
    rules_.clear();
    for (const auto& row : readCsv(path)) {
        BehaviorRule rule;
        rule.id = row.at("id");
        rule.name = row.at("name");
        rule.severity = toLower(row.at("severity"));
        rule.tactic = row.at("tactic");
        rule.description = row.at("description");

        for (const auto& conditionText : split(row.at("conditions"), ';')) {
            auto condition = parseCondition(conditionText);
            if (!condition.field.empty()) {
                rule.conditions.push_back(condition);
            }
        }
        rules_.push_back(rule);
    }
    return true;
}

std::vector<Detection> BehaviorDetector::evaluate(const Event& event) const {
    std::vector<Detection> detections;
    for (const auto& rule : rules_) {
        bool matched = !rule.conditions.empty();
        for (const auto& condition : rule.conditions) {
            if (!matchesCondition(event, condition)) {
                matched = false;
                break;
            }
        }

        if (matched) {
            detections.push_back({
                event.id,
                "behavior",
                rule.id,
                rule.severity,
                rule.tactic,
                rule.name + " - " + rule.description,
                0.80
            });
        }
    }
    return detections;
}

} // namespace threatfusion
