#include "threatfusion/ThreatIntel.h"

#include "threatfusion/Csv.h"

namespace threatfusion {

bool ThreatIntel::loadIocs(const std::string& path) {
    iocs_.clear();
    for (const auto& row : readCsv(path)) {
        Ioc ioc;
        ioc.type = toLower(row.at("type"));
        ioc.value = toLower(row.at("value"));
        ioc.severity = toLower(row.at("severity"));
        ioc.malwareFamily = row.at("malware_family");
        ioc.description = row.at("description");
        iocs_.push_back(ioc);
    }
    return true;
}

std::vector<Detection> ThreatIntel::correlate(const Event& event) const {
    std::vector<Detection> detections;
    const auto srcIp = toLower(event.srcIp);
    const auto dstIp = toLower(event.dstIp);
    const auto payloadHash = toLower(event.payloadHash);

    for (const auto& ioc : iocs_) {
        bool matched = false;
        if (ioc.type == "ip") {
            matched = (ioc.value == srcIp || ioc.value == dstIp);
        } else if (ioc.type == "hash") {
            matched = (!payloadHash.empty() && ioc.value == payloadHash);
        } else if (ioc.type == "protocol") {
            matched = (ioc.value == toLower(event.protocol));
        }

        if (matched) {
            detections.push_back({
                event.id,
                "threat_intel",
                ioc.type + ":" + ioc.value,
                ioc.severity,
                ioc.malwareFamily,
                ioc.description,
                0.95
            });
        }
    }
    return detections;
}

} // namespace threatfusion
