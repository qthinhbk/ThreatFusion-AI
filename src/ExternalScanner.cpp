#include "threatfusion/ExternalScanner.h"

#include "threatfusion/Csv.h"

#include <array>
#include <cstdio>
#include <fstream>
#include <regex>
#include <sstream>

#ifdef _WIN32
#include <direct.h>
#define POPEN _popen
#define PCLOSE _pclose
#else
#include <sys/stat.h>
#define POPEN popen
#define PCLOSE pclose
#endif

namespace threatfusion {

static std::string quote(const std::string& value) {
    return "\"" + value + "\"";
}

static void makeDirectory(const std::string& path) {
    if (path.empty()) {
        return;
    }
#ifdef _WIN32
    _mkdir(path.c_str());
#else
    mkdir(path.c_str(), 0755);
#endif
}

static std::string runCommand(const std::string& command) {
    std::array<char, 512> buffer{};
    std::string output;
#ifdef _WIN32
    const auto shellCommand = "cmd /C " + quote(command);
    FILE* pipe = POPEN(shellCommand.c_str(), "r");
#else
    FILE* pipe = POPEN(command.c_str(), "r");
#endif
    if (!pipe) {
        return "";
    }
    while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe) != nullptr) {
        output += buffer.data();
    }
    PCLOSE(pipe);
    return output;
}

void ExternalScanner::setYara(const std::string& executable, const std::string& rulesPath) {
    yaraExecutable_ = executable;
    yaraRulesPath_ = rulesPath;
}

void ExternalScanner::setSnort(const std::string& executable, const std::string& configPath, const std::string& pcapPath) {
    snortExecutable_ = executable;
    snortConfigPath_ = configPath;
    snortPcapPath_ = pcapPath;
}

void ExternalScanner::setSuricata(const std::string& executable,
                                  const std::string& rulesPath,
                                  const std::string& pcapPath,
                                  const std::string& logDir) {
    suricataExecutable_ = executable;
    suricataRulesPath_ = rulesPath;
    suricataPcapPath_ = pcapPath;
    suricataLogDir_ = logDir.empty() ? "out/suricata" : logDir;
}

static Detection parseSuricataFastLog(const std::string& eventId, const std::string& line) {
    Detection detection;
    detection.eventId = eventId;
    detection.source = "suricata";
    detection.indicator = line;
    detection.severity = "high";
    detection.category = "Network Signature";
    detection.description = "Suricata signature matched traffic in PCAP.";
    detection.confidence = 0.88;
    detection.assetRole = "network";
    if (line.find("BACnet") != std::string::npos) {
        detection.protocol = "bacnet";
        detection.assetRole = "hmi";
    } else if (line.find("Modbus") != std::string::npos || line.find("S7Comm") != std::string::npos || line.find("CODESYS") != std::string::npos) {
        detection.protocol = line.find("CODESYS") != std::string::npos ? "codesys" : line.find("S7Comm") != std::string::npos ? "s7comm" : "modbus";
        detection.assetRole = "plc";
    } else if (line.find("IEC-104") != std::string::npos || line.find("DNP3") != std::string::npos) {
        detection.protocol = line.find("DNP3") != std::string::npos ? "dnp3" : "iec104";
        detection.assetRole = "rtu";
    } else if (line.find("OPC UA") != std::string::npos) {
        detection.protocol = "opcua";
        detection.assetRole = "historian";
    }

    const std::regex flowPattern(R"(^(\S+).*?\{([^}]+)\}\s+([^:\s]+):\d+\s+->\s+([^:\s]+):\d+)");
    std::smatch match;
    if (std::regex_search(line, match, flowPattern)) {
        detection.timestamp = match[1].str();
        if (detection.protocol.empty() || detection.protocol == "pcap") {
            detection.protocol = toLower(match[2].str());
        }
        detection.srcIp = match[3].str();
        detection.dstIp = match[4].str();
    } else {
        detection.timestamp = "pcap";
        detection.protocol = "pcap";
    }

    return detection;
}

std::vector<Detection> ExternalScanner::evaluate(const Event& event) const {
    std::vector<Detection> detections;
    if (yaraExecutable_.empty() || yaraRulesPath_.empty() || event.payloadPath.empty()) {
        return detections;
    }

    const auto output = runCommand(quote(yaraExecutable_) + " " + quote(yaraRulesPath_) + " " + quote(event.payloadPath));
    for (const auto& line : split(output, '\n')) {
        if (trim(line).empty()) {
            continue;
        }
        detections.push_back({
            event.id,
            "yara",
            line,
            "critical",
            "Malware Signature",
            "YARA rule matched payload sample.",
            0.90
        });
    }
    return detections;
}

std::vector<Detection> ExternalScanner::evaluatePcap() const {
    std::vector<Detection> detections;
    if (!suricataExecutable_.empty() && !suricataRulesPath_.empty() && !suricataPcapPath_.empty()) {
        const auto fastLog = suricataLogDir_ + "/fast.log";
        ensureParentDirectory(fastLog);
        makeDirectory(suricataLogDir_);
        std::remove(fastLog.c_str());
        const auto command = quote(suricataExecutable_) + " -r " + quote(suricataPcapPath_) +
            " -S " + quote(suricataRulesPath_) + " -l " + quote(suricataLogDir_) + " -k none";
        runCommand(command);

        std::ifstream file(fastLog);
        std::string line;
        int index = 0;
        while (std::getline(file, line)) {
            if (trim(line).empty()) {
                continue;
            }
            ++index;
            detections.push_back(parseSuricataFastLog("SURICATA-" + std::to_string(index), line));
        }
    }

    if (snortExecutable_.empty() || snortConfigPath_.empty() || snortPcapPath_.empty()) {
        return detections;
    }

    const auto command = quote(snortExecutable_) + " -q -A csv -c " + quote(snortConfigPath_) + " -r " + quote(snortPcapPath_);
    const auto output = runCommand(command);
    int index = 0;
    for (const auto& line : split(output, '\n')) {
        if (trim(line).empty()) {
            continue;
        }
        ++index;
        detections.push_back({
            "SNORT-" + std::to_string(index),
            "snort",
            line,
            "high",
            "Network Signature",
            "Snort signature matched traffic in PCAP.",
            0.88
        });
    }
    return detections;
}

} // namespace threatfusion
