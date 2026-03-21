#pragma once

#include "threatfusion/Event.h"

#include <string>
#include <vector>

namespace threatfusion {

struct IngestionOptions {
    std::string format = "csv";
    std::string tsharkPath = "tshark";
};

std::vector<Event> loadEvents(const std::string& path, const IngestionOptions& options);
std::vector<Event> loadEvents(const std::string& path, const std::string& format);

} // namespace threatfusion
