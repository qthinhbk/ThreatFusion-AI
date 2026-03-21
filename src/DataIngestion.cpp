#include "threatfusion/DataIngestion.h"

#include "threatfusion/Csv.h"

#include <array>
#include <cstdio>
#include <fstream>
#include <stdexcept>

#ifdef _WIN32
#define POPEN _popen
#define PCLOSE _pclose
#else
#define POPEN popen
#define PCLOSE pclose
#endif

namespace threatfusion {

static int parseInt(const CsvRow& row, const std::string& key, int fallback = 0) {
    const auto found = row.find(key);
    if (found == row.end() || found->second.empty()) {
        return fallback;
    }
    return std::stoi(found->second);
}

static std::vector<Event> loadCsvEvents(const std::string& path) {
    std::vector<Event> events;
    for (const auto& row : readCsv(path)) {
        Event event;
        event.id = row.at("id");
        event.timestamp = row.at("timestamp");
        event.srcIp = row.at("src_ip");
        event.dstIp = row.at("dst_ip");
        event.protocol = row.at("protocol");
        event.functionCode = parseInt(row, "function_code", -1);
        event.assetRole = row.at("asset_role");
        event.payloadHash = row.at("payload_hash");
        event.payloadPath = row.count("payload_path") ? row.at("payload_path") : "";
        event.bytes = parseInt(row, "bytes", 0);
        event.action = row.at("action");
        event.label = row.count("label") ? row.at("label") : "";
        events.push_back(event);
    }
    return events;
}

static std::string jsonValue(const std::string& line, const std::string& key) {
    const auto pattern = "\"" + key + "\"";
    auto keyPos = line.find(pattern);
    if (keyPos == std::string::npos) {
        return "";
    }
    auto colon = line.find(':', keyPos + pattern.size());
    if (colon == std::string::npos) {
        return "";
    }
    auto valueStart = line.find_first_not_of(" \t", colon + 1);
    if (valueStart == std::string::npos) {
        return "";
    }

    if (line[valueStart] == '"') {
        ++valueStart;
        auto valueEnd = line.find('"', valueStart);
        if (valueEnd == std::string::npos) {
            return "";
        }
        return line.substr(valueStart, valueEnd - valueStart);
    }

    auto valueEnd = line.find_first_of(",}", valueStart);
    if (valueEnd == std::string::npos) {
        valueEnd = line.size();
    }
    return trim(line.substr(valueStart, valueEnd - valueStart));
}

static int jsonInt(const std::string& line, const std::string& key, int fallback = 0) {
    const auto value = jsonValue(line, key);
    if (value.empty()) {
        return fallback;
    }
    return std::stoi(value);
}

static double jsonDouble(const std::string& line, const std::string& key, double fallback = 0.0) {
    const auto value = jsonValue(line, key);
    if (value.empty()) {
        return fallback;
    }
    try {
        return std::stod(value);
    } catch (...) {
        return fallback;
    }
}

// Parse "extra_features":[0.1,0.2,...] JSON array into a vector<double>.
static std::vector<double> jsonDoubleArray(const std::string& line, const std::string& key) {
    std::vector<double> result;
    const auto pattern = "\"" + key + "\"";
    auto keyPos = line.find(pattern);
    if (keyPos == std::string::npos) {
        return result;
    }
    auto bracketStart = line.find('[', keyPos);
    if (bracketStart == std::string::npos) {
        return result;
    }
    auto bracketEnd = line.find(']', bracketStart);
    if (bracketEnd == std::string::npos) {
        return result;
    }
    auto content = line.substr(bracketStart + 1, bracketEnd - bracketStart - 1);
    // Split by commas and parse doubles
    std::string::size_type pos = 0;
    while (pos < content.size()) {
        auto commaPos = content.find(',', pos);
        auto token = (commaPos == std::string::npos)
            ? content.substr(pos)
            : content.substr(pos, commaPos - pos);
        // Trim whitespace
        auto start = token.find_first_not_of(" \t");
        if (start != std::string::npos) {
            try {
                result.push_back(std::stod(token.substr(start)));
            } catch (...) {
                result.push_back(0.0);
            }
        }
        if (commaPos == std::string::npos) break;
        pos = commaPos + 1;
    }
    return result;
}

static std::vector<Event> loadJsonlEvents(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error("Cannot open JSONL file: " + path);
    }

    std::vector<Event> events;
    std::string line;
    while (std::getline(file, line)) {
        if (trim(line).empty()) {
            continue;
        }
        Event event;
        event.id = jsonValue(line, "id");
        event.timestamp = jsonValue(line, "timestamp");
        event.srcIp = jsonValue(line, "src_ip");
        event.dstIp = jsonValue(line, "dst_ip");
        event.protocol = jsonValue(line, "protocol");
        event.functionCode = jsonInt(line, "function_code", -1);
        event.assetRole = jsonValue(line, "asset_role");
        event.payloadHash = jsonValue(line, "payload_hash");
        event.payloadPath = jsonValue(line, "payload_path");
        event.bytes = jsonInt(line, "bytes", 0);
        event.action = jsonValue(line, "action");
        event.label = jsonValue(line, "label");
        event.extraFeatures = jsonDoubleArray(line, "extra_features");
        events.push_back(event);
    }
    return events;
}

static std::string quote(const std::string& value) {
    return "\"" + value + "\"";
}

static std::string runCommand(const std::string& command) {
    std::array<char, 2048> buffer{};
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

static int firstFunctionCode(const std::vector<std::string>& columns) {
    for (std::size_t i = 5; i <= 9 && i < columns.size(); ++i) {
        if (!columns[i].empty()) {
            try {
                return std::stoi(columns[i]);
            } catch (...) {
                return -1;
            }
        }
    }
    return -1;
}

static int safeInt(const std::string& value, int fallback = 0) {
    if (value.empty()) {
        return fallback;
    }
    try {
        return std::stoi(value);
    } catch (...) {
        return fallback;
    }
}

static std::string normalizeProtocol(const std::string& raw) {
    const auto value = toLower(raw);
    if (value.find("modbus") != std::string::npos) return "modbus";
    if (value.find("dnp3") != std::string::npos) return "dnp3";
    if (value.find("iec") != std::string::npos || value.find("104") != std::string::npos) return "iec104";
    if (value.find("61850") != std::string::npos || value.find("mms") != std::string::npos) return "iec61850";
    if (value.find("opc") != std::string::npos) return "opcua";
    if (value.find("bacnet") != std::string::npos || value.find("bvlc") != std::string::npos) return "bacnet";
    if (value.find("codesys") != std::string::npos) return "codesys";
    if (value.find("s7") != std::string::npos) return "s7comm";
    return value.empty() ? "unknown" : value;
}

static std::string inferAssetRole(const std::string& protocol) {
    const auto value = toLower(protocol);
    if (value == "modbus" || value == "s7comm" || value == "codesys") return "plc";
    if (value == "dnp3" || value == "iec104" || value == "iec61850") return "rtu";
    if (value == "opcua") return "historian";
    if (value == "bacnet") return "hmi";
    return "unknown";
}

static std::vector<Event> loadPcapEvents(const std::string& path, const std::string& tsharkPath) {
    const auto command =
        quote(tsharkPath) + " -r " + quote(path) +
        " -T fields -E separator=, -E quote=d -E occurrence=f"
        " -e frame.number -e frame.time_epoch -e ip.src -e ip.dst -e _ws.col.Protocol"
        " -e modbus.func_code -e dnp3.al.func -e 104asdu.typeid -e opcua.transport.type -e bacapp.type -e frame.len";

    const auto output = runCommand(command);
    if (output.empty()) {
        throw std::runtime_error("No PCAP events parsed. Is tshark installed and in PATH?");
    }

    std::vector<Event> events;
    for (const auto& line : split(output, '\n')) {
        if (trim(line).empty()) {
            continue;
        }
        const auto columns = parseCsvLine(line);
        if (columns.size() < 5) {
            continue;
        }
        Event event;
        event.id = "PCAP-" + columns[0];
        event.timestamp = columns.size() > 1 ? columns[1] : "";
        event.srcIp = columns.size() > 2 ? columns[2] : "";
        event.dstIp = columns.size() > 3 ? columns[3] : "";
        event.protocol = normalizeProtocol(columns.size() > 4 ? columns[4] : "");
        event.functionCode = firstFunctionCode(columns);
        event.assetRole = inferAssetRole(event.protocol);
        event.payloadHash = "";
        event.bytes = columns.size() > 10 ? safeInt(columns[10], 0) : 0;
        event.action = "observed";
        event.label = "";
        events.push_back(event);
    }
    return events;
}

std::vector<Event> loadEvents(const std::string& path, const IngestionOptions& options) {
    const auto normalized = toLower(options.format);
    if (normalized == "csv") {
        return loadCsvEvents(path);
    }
    if (normalized == "jsonl" || normalized == "json") {
        return loadJsonlEvents(path);
    }
    if (normalized == "pcap") {
        return loadPcapEvents(path, options.tsharkPath);
    }
    throw std::runtime_error("Unsupported event format: " + options.format);
}

std::vector<Event> loadEvents(const std::string& path, const std::string& format) {
    IngestionOptions options;
    options.format = format;
    return loadEvents(path, options);
}

} // namespace threatfusion
