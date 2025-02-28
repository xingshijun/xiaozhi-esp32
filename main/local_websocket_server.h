#pragma once

#include <esp_http_server.h>
// WebSocket API 现在包含在 esp_http_server.h 中，不再需要单独的头文件
// #include <esp_websocket_server.h>  // 删除这行
#include <functional>
#include <string>

class LocalWebsocketServer {
public:
    static LocalWebsocketServer& GetInstance();
    
    bool Start(uint16_t port = 80);
    void Stop();

    // 设置回调函数
    void OnGetConfig(std::function<std::string()> callback) { get_config_callback_ = callback; }
    void OnSetConfig(std::function<bool(const std::string&)> callback) { set_config_callback_ = callback; }
    void OnReboot(std::function<void()> callback) { reboot_callback_ = callback; }

private:
    LocalWebsocketServer() = default;
    ~LocalWebsocketServer();

    static esp_err_t HandleWebSocket(httpd_req_t *req);
    static esp_err_t HandleHttpRequest(httpd_req_t *req);
    
    httpd_handle_t server_ = nullptr;
    std::function<std::string()> get_config_callback_;
    std::function<bool(const std::string&)> set_config_callback_;
    std::function<void()> reboot_callback_;
};