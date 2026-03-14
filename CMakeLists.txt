cmake_minimum_required(VERSION 3.16)

project(ThreatFusionAI VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_library(threatfusion_core
    src/BaselineDetector.cpp
    src/BehaviorDetector.cpp
    src/Csv.cpp
    src/DataIngestion.cpp
    src/Evaluator.cpp
    src/ExternalScanner.cpp
    src/IncidentAggregator.cpp
    src/IsolationForestDetector.cpp
    src/RiskScorer.cpp
    src/ThreatIntel.cpp
    src/SocketReceiver.cpp
    src/LSTMDetector.cpp
)

target_include_directories(threatfusion_core PUBLIC include)

if(WIN32)
    target_link_libraries(threatfusion_core PUBLIC ws2_32)
endif()

option(USE_LIBTORCH "Use LibTorch (PyTorch C++ API)" OFF)
if(USE_LIBTORCH)
    find_package(Torch REQUIRED)
    target_compile_definitions(threatfusion_core PUBLIC USE_LIBTORCH)
    target_link_libraries(threatfusion_core PUBLIC ${TORCH_LIBRARIES})
endif()

add_executable(threatfusion src/main.cpp)
target_link_libraries(threatfusion PRIVATE threatfusion_core)

enable_testing()

add_executable(threatfusion_tests tests/test_engine.cpp)
target_link_libraries(threatfusion_tests PRIVATE threatfusion_core)
add_test(NAME threatfusion_tests COMMAND threatfusion_tests)
