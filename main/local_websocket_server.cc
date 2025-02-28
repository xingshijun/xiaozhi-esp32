#include "local_websocket_server.h"
#include <esp_log.h>
#include <cstring>
#include <cJSON.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>

#define TAG "WebSocketServer"
#define WS_PING_INTERVAL_MS 30000  // 30秒发送一次 ping
#define WS_PING_TIMEOUT_MS 120000  // 120秒没有响应则断开连接

// 生成 WebSocket 接受密钥
static void GenerateAcceptKey(const char* client_key, char* accept_key) {
    const char* magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char sha1_hash[20];
    char combined_key[128];
    
    // 组合客户端密钥和魔术字符串
    snprintf(combined_key, sizeof(combined_key), "%s%s", client_key, magic);
    
    // 计算 SHA1
    mbedtls_sha1_context sha1_ctx;
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    mbedtls_sha1_update(&sha1_ctx, (const unsigned char*)combined_key, strlen(combined_key));
    mbedtls_sha1_finish(&sha1_ctx, sha1_hash);
    mbedtls_sha1_free(&sha1_ctx);
    
    // Base64 编码
    size_t out_len;
    mbedtls_base64_encode((unsigned char*)accept_key, 32, &out_len, sha1_hash, 20);
    accept_key[out_len] = '\0';
}

// WebSocket 处理回调
esp_err_t LocalWebsocketServer::HandleWebSocket(httpd_req_t *req) {
    ESP_LOGI(TAG, "\n=== WebSocket handler ===");
    ESP_LOGI(TAG, "URI: %s", req->uri);
    ESP_LOGI(TAG, "Method: %s", (req->method == HTTP_GET) ? "GET" : "OTHER");
    
    // 打印所有头部
    const char* headers[] = {
        "Host",
        "Connection",
        "Upgrade",
        "Sec-WebSocket-Key",
        "Sec-WebSocket-Version",
        "Sec-WebSocket-Protocol",
        "User-Agent",
        "Accept",
        "Accept-Encoding",
        "Accept-Language",
        "Origin"
    };
    
    bool is_websocket = false;
    char ws_key[64] = {0};
    
    for (const char* header : headers) {
        size_t len = httpd_req_get_hdr_value_len(req, header);
        if (len > 0) {
            char* value = (char*)malloc(len + 1);
            if (value) {
                if (httpd_req_get_hdr_value_str(req, header, value, len + 1) == ESP_OK) {
                    ESP_LOGI(TAG, "Header %s: %s", header, value);
                    
                    if (strcmp(header, "Upgrade") == 0 && 
                        strcasecmp(value, "websocket") == 0) {
                        is_websocket = true;
                    }
                    
                    if (strcmp(header, "Sec-WebSocket-Key") == 0) {
                        strncpy(ws_key, value, sizeof(ws_key) - 1);
                    }
                }
                free(value);
            }
        }
    }
    
    if (req->method == HTTP_GET && is_websocket && strlen(ws_key) > 0) {
        ESP_LOGI(TAG, "Valid WebSocket request detected");
        
        char accept_key[32] = {0};
        GenerateAcceptKey(ws_key, accept_key);
        ESP_LOGI(TAG, "Accept key: %s", accept_key);
        
        httpd_resp_set_status(req, "101 Switching Protocols");
        httpd_resp_set_type(req, "text/plain");
        
        esp_err_t err;
        err = httpd_resp_set_hdr(req, "Upgrade", "websocket");
        ESP_LOGI(TAG, "Set Upgrade header: %d", err);
        
        err = httpd_resp_set_hdr(req, "Connection", "Upgrade");
        ESP_LOGI(TAG, "Set Connection header: %d", err);
        
        err = httpd_resp_set_hdr(req, "Sec-WebSocket-Accept", accept_key);
        ESP_LOGI(TAG, "Set Accept header: %d", err);
        
        err = httpd_resp_send(req, NULL, 0);
        ESP_LOGI(TAG, "Response sent: %d", err);
        
        return err;
    }
    
    ESP_LOGI(TAG, "Invalid WebSocket request");
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid WebSocket request");
    return ESP_FAIL;
}

// 通用请求处理函数
static esp_err_t HandleAllRequests(httpd_req_t *req) {
    ESP_LOGI(TAG, "\n=== Catch-all handler ===");
    ESP_LOGI(TAG, "URI: %s", req->uri);
    ESP_LOGI(TAG, "Method: %s", (req->method == HTTP_GET) ? "GET" : "OTHER");
    
    // 打印所有头部
    size_t headers_count = httpd_req_get_hdr_value_len(req, NULL);
    ESP_LOGI(TAG, "Number of headers: %d", headers_count);
    
    // 返回 404
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not found");
    return ESP_OK;
}

// 启动服务器
bool LocalWebsocketServer::Start(uint16_t port) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = port;
    config.lru_purge_enable = true;
    config.max_uri_handlers = 8;
    config.max_resp_headers = 8;
    config.recv_wait_timeout = 10;
    config.send_wait_timeout = 10;
    config.max_open_sockets = 3;     // 增加最大连接数
    config.backlog_conn = 5;         // 增加等待队列
    config.core_id = 0;             // 指定核心
    config.stack_size = 8192;       // 增加栈大小
    
    ESP_LOGI(TAG, "Starting server with config:");
    ESP_LOGI(TAG, "Port: %d, Max handlers: %d, Stack: %d",
             config.server_port, config.max_uri_handlers, config.stack_size);
    
    if (httpd_start(&server_, &config) == ESP_OK) {
        // 注册 WebSocket 处理程序
        httpd_uri_t ws = {
            .uri = "/ws",
            .method = HTTP_GET,
            .handler = HandleWebSocket,
            .user_ctx = nullptr
        };
        
        ESP_LOGI(TAG, "Registering WebSocket handler");
        esp_err_t ret = httpd_register_uri_handler(server_, &ws);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to register WebSocket handler: %d", ret);
            return false;
        }
        
        // 注册一个通用处理程序来捕获所有请求
        httpd_uri_t catch_all = {
            .uri = "/*",
            .method = HTTP_GET,
            .handler = HandleAllRequests,
            .user_ctx = nullptr
        };
        
        ESP_LOGI(TAG, "Registering catch-all handler");
        ret = httpd_register_uri_handler(server_, &catch_all);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Failed to register catch-all handler: %d", ret);
        }
        
        ESP_LOGI(TAG, "Server started successfully");
        return true;
    }
    
    ESP_LOGE(TAG, "Failed to start server");
    return false;
}

// 停止服务器
void LocalWebsocketServer::Stop() {
    if (server_) {
        httpd_stop(server_);
        server_ = nullptr;
    }
}

// 析构函数
LocalWebsocketServer::~LocalWebsocketServer() {
    Stop();
}

// 获取单例实例
LocalWebsocketServer& LocalWebsocketServer::GetInstance() {
    static LocalWebsocketServer instance;
    return instance;
}