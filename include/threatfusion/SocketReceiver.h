#pragma once

#include "Event.h"
#include <string>
#include <functional>
#include <thread>
#include <atomic>

namespace threatfusion {

class SocketReceiver {
public:
    SocketReceiver();
    ~SocketReceiver();

    bool start(int port, std::function<void(const Event&)> callback);
    void stop();

private:
    void listenLoop(int port, std::function<void(const Event&)> callback);
    
    std::thread listenerThread_;
    std::atomic<bool> running_;
#ifdef _WIN32
    unsigned __int64 serverSocket_;
#else
    int serverSocket_;
#endif
};

} // namespace threatfusion
