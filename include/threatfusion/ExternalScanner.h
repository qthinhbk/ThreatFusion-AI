#pragma once

#include "threatfusion/Detection.h"
#include "threatfusion/Event.h"

#include <string>
#include <vector>

namespace threatfusion {

class ExternalScanner {
public:
    void setYara(const std::string& executable, const std::string& rulesPath);
    void setSnort(const std::string& executable, const std::string& configPath, const std::string& pcapPath);
    void setSuricata(const std::string& executable,
                     const std::string& rulesPath,
                     const std::string& pcapPath,
                     const std::string& logDir);
    std::vector<Detection> evaluate(const Event& event) const;
    std::vector<Detection> evaluatePcap() const;

private:
    std::string yaraExecutable_;
    std::string yaraRulesPath_;
    std::string snortExecutable_;
    std::string snortConfigPath_;
    std::string snortPcapPath_;
    std::string suricataExecutable_;
    std::string suricataRulesPath_;
    std::string suricataPcapPath_;
    std::string suricataLogDir_;
};

} // namespace threatfusion
