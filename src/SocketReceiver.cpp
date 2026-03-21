#include "threatfusion/SocketReceiver.h"
#include "threatfusion/Csv.h"

#include <iostream>
#include <sstream>
#include <vector>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef SOCKET socket_t;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
typedef int socket_t;
#define INVALID_SOCKET -1
#define SOCKET_ERROR -1
#define closesocket close
#endif

namespace threatfusion {

static std::string jsonValue(const std::string &line, const std::string &key) {
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

static int jsonInt(const std::string &line, const std::string &key,
                   int fallback = 0) {
  const auto value = jsonValue(line, key);
  if (value.empty()) {
    return fallback;
  }
  try {
    return std::stoi(value);
  } catch (...) {
    return fallback;
  }
}

SocketReceiver::SocketReceiver() : running_(false) {
#ifdef _WIN32
  serverSocket_ = INVALID_SOCKET;
#else
  serverSocket_ = -1;
#endif
}

SocketReceiver::~SocketReceiver() { stop(); }

bool SocketReceiver::start(int port,
                           std::function<void(const Event &)> callback) {
  if (running_) {
    return false;
  }
  running_ = true;
  listenerThread_ =
      std::thread(&SocketReceiver::listenLoop, this, port, callback);
  return true;
}

void SocketReceiver::stop() {
  if (!running_) {
    return;
  }
  running_ = false;

#ifdef _WIN32
  if (serverSocket_ != INVALID_SOCKET) {
    closesocket(serverSocket_);
    serverSocket_ = INVALID_SOCKET;
  }
#else
  if (serverSocket_ >= 0) {
    closesocket(serverSocket_);
    serverSocket_ = -1;
  }
#endif

  if (listenerThread_.joinable()) {
    listenerThread_.join();
  }
}

void SocketReceiver::listenLoop(int port,
                                std::function<void(const Event &)> callback) {
#ifdef _WIN32
  WSADATA wsaData;
  if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
    std::cerr << "[SocketReceiver] WSAStartup failed.\n";
    running_ = false;
    return;
  }
#endif

  struct sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = INADDR_ANY;
  address.sin_port = htons(port);

  socket_t serverFd = socket(AF_INET, SOCK_STREAM, 0);
#ifdef _WIN32
  serverSocket_ = serverFd;
  if (serverFd == INVALID_SOCKET) {
    std::cerr << "[SocketReceiver] Socket creation failed.\n";
    WSACleanup();
    running_ = false;
    return;
  }
#else
  serverSocket_ = serverFd;
  if (serverFd < 0) {
    std::cerr << "[SocketReceiver] Socket creation failed.\n";
    running_ = false;
    return;
  }
#endif

  int opt = 1;
#ifdef _WIN32
  setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt,
             sizeof(opt));
#else
  setsockopt(serverFd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
#endif

  if (bind(serverFd, (struct sockaddr *)&address, sizeof(address)) ==
      SOCKET_ERROR) {
    std::cerr << "[SocketReceiver] Bind failed on port " << port << ".\n";
    closesocket(serverFd);
#ifdef _WIN32
    WSACleanup();
#endif
    running_ = false;
    return;
  }

  if (listen(serverFd, 3) == SOCKET_ERROR) {
    std::cerr << "[SocketReceiver] Listen failed.\n";
    closesocket(serverFd);
#ifdef _WIN32
    WSACleanup();
#endif
    running_ = false;
    return;
  }

  std::cout << "[SocketReceiver] Listening on port " << port << "...\n";

  while (running_) {
    struct sockaddr_in clientAddr{};
    socklen_t addrLen = sizeof(clientAddr);
    socket_t clientFd =
        accept(serverFd, (struct sockaddr *)&clientAddr, &addrLen);

#ifdef _WIN32
    if (clientFd == INVALID_SOCKET) {
      if (!running_)
        break;
      continue;
    }
#else
    if (clientFd < 0) {
      if (!running_)
        break;
      continue;
    }
#endif

#ifdef _WIN32
    const char *ipStr = inet_ntoa(clientAddr.sin_addr);
#else
    char ipStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(clientAddr.sin_addr), ipStr, INET_ADDRSTRLEN);
#endif
    std::cout << "[SocketReceiver] Connection accepted from " << ipStr << "\n";

    std::string bufferAccumulator;
    char buffer[1024];

    while (running_) {
      int valRead = recv(clientFd, buffer, sizeof(buffer) - 1, 0);
      if (valRead <= 0) {
        std::cout << "[SocketReceiver] Connection closed or read error.\n";
        break;
      }

      buffer[valRead] = '\0';
      bufferAccumulator += buffer;

      size_t newlinePos;
      while ((newlinePos = bufferAccumulator.find('\n')) != std::string::npos) {
        std::string line = bufferAccumulator.substr(0, newlinePos);
        bufferAccumulator.erase(0, newlinePos + 1);

        line = trim(line);
        if (line.empty()) {
          continue;
        }

        // Parse line to Event
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

        // Invoke callback
        callback(event);
      }
    }
    closesocket(clientFd);
  }

  closesocket(serverFd);
#ifdef _WIN32
  WSACleanup();
#endif
  std::cout << "[SocketReceiver] Listener thread stopped.\n";
}

} // namespace threatfusion
