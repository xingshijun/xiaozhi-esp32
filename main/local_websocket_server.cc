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
    char* header = nullptr;
    size_t header_len;

    // 检查 Connection 头
    header_len = httpd_req_get_hdr_value_len(req, "Connection");
    if (header_len > 0) {
        header = (char*)malloc(header_len + 1);
        if (httpd_req_get_hdr_value_str(req, "Connection", header, header_len + 1) == ESP_OK) {
            if (strcasestr(header, "upgrade") == nullptr) {
                free(header);
                return ESP_FAIL;
            }
        }
        free(header);
    }

    // 检查 Upgrade 头
    header_len = httpd_req_get_hdr_value_len(req, "Upgrade");
    if (header_len > 0) {
        header = (char*)malloc(header_len + 1);
        if (httpd_req_get_hdr_value_str(req, "Upgrade", header, header_len + 1) == ESP_OK) {
            if (strcasecmp(header, "websocket") != 0) {
                free(header);
                return ESP_FAIL;
            }
        }
        free(header);
    }

    // 获取 WebSocket 版本
    header_len = httpd_req_get_hdr_value_len(req, "Sec-WebSocket-Version");
    if (header_len > 0) {
        header = (char*)malloc(header_len + 1);
        if (httpd_req_get_hdr_value_str(req, "Sec-WebSocket-Version", header, header_len + 1) == ESP_OK) {
            if (strcmp(header, "13") != 0) {
                free(header);
                return ESP_FAIL;
            }
        }
        free(header);
    }

    // 获取客户端密钥
    header_len = httpd_req_get_hdr_value_len(req, "Sec-WebSocket-Key");
    if (header_len > 0) {
        char client_key[32] = {0};
        char accept_key[32] = {0};
        
        if (httpd_req_get_hdr_value_str(req, "Sec-WebSocket-Key", client_key, sizeof(client_key)) == ESP_OK) {
            // 生成接受密钥
            GenerateAcceptKey(client_key, accept_key);
            
            // 设置响应头
            httpd_resp_set_status(req, "101 Switching Protocols");
            httpd_resp_set_hdr(req, "Upgrade", "websocket");
            httpd_resp_set_hdr(req, "Connection", "Upgrade");
            httpd_resp_set_hdr(req, "Sec-WebSocket-Accept", accept_key);
            
            // 发送空响应体完成握手
            httpd_resp_send(req, nullptr, 0);
            
            ESP_LOGI(TAG, "WebSocket handshake successful");
            return ESP_OK;
        }
    }

    // 如果是数据帧
    if (req->content_len > 0) {
        uint8_t *buf = (uint8_t*)malloc(req->content_len);
        if (!buf) {
            return ESP_ERR_NO_MEM;
        }

        int ret = httpd_req_recv(req, (char*)buf, req->content_len);
        if (ret <= 0) {
            free(buf);
            return ESP_FAIL;
        }

        // 处理 WebSocket 数据帧
        if (buf[0] & 0x80) {  // FIN bit set
            uint8_t opcode = buf[0] & 0x0F;
            uint8_t mask = buf[1] & 0x80;
            uint64_t payload_len = buf[1] & 0x7F;
            size_t header_len = 2;

            // 处理扩展长度
            if (payload_len == 126) {
                payload_len = (buf[2] << 8) | buf[3];
                header_len += 2;
            } else if (payload_len == 127) {
                payload_len = 0;
                for (int i = 0; i < 8; i++) {
                    payload_len = (payload_len << 8) | buf[2 + i];
                }
                header_len += 8;
            }

            // 处理掩码
            uint8_t mask_key[4] = {0};
            if (mask) {
                memcpy(mask_key, buf + header_len, 4);
                header_len += 4;
            }

            // 解码数据
            for (size_t i = 0; i < payload_len; i++) {
                buf[header_len + i] ^= mask_key[i % 4];
            }

            // 处理不同类型的帧
            switch (opcode) {
                case 0x1:  // 文本帧
                    {
                        buf[header_len + payload_len] = 0;  // Null-terminate
                        char* payload = (char*)(buf + header_len);
                        
                        if (strcmp(payload, "ping") == 0) {
                            // 发送 pong 响应
                            const char* pong = "pong";
                            httpd_resp_send(req, pong, strlen(pong));
                        } else {
                            // 处理 JSON 消息
                            auto& server = LocalWebsocketServer::GetInstance();
                            cJSON* root = cJSON_Parse(payload);
                            if (root) {
                                cJSON* type = cJSON_GetObjectItem(root, "type");
                                if (type && type->valuestring) {
                                    std::string type_str = type->valuestring;
                                    std::string response;
                                    
                                    if (type_str == "get_config" && server.get_config_callback_) {
                                        std::string config_data = server.get_config_callback_();
                                        response = "{\"type\":\"get_config\", \"data\":" + config_data + "}";
                                    }
                                    else if (type_str == "set_config" && server.set_config_callback_) {
                                        cJSON* config = cJSON_GetObjectItem(root, "config");
                                        if (config) {
                                            char* config_str = cJSON_PrintUnformatted(config);
                                            if (config_str) {
                                                bool success = server.set_config_callback_(config_str);
                                                free(config_str);
                                                response = "{\"type\":\"set_config\", \"status\":\"" + std::string(success ? "success" : "failed") + "\"}";
                                            }
                                        }
                                    }
                                    else if (type_str == "reboot" && server.reboot_callback_) {
                                        response = "{\"type\":\"reboot\", \"status\":\"success\"}";
                                        server.reboot_callback_();
                                    }

                                    // 发送响应
                                    if (!response.empty()) {
                                        // 构造 WebSocket 文本帧
                                        size_t frame_len = response.length() + 2;
                                        uint8_t* frame = (uint8_t*)malloc(frame_len);
                                        if (frame) {
                                            frame[0] = 0x81;  // FIN + Text frame
                                            frame[1] = response.length();
                                            memcpy(frame + 2, response.c_str(), response.length());
                                            httpd_resp_send(req, (const char*)frame, frame_len);
                                            free(frame);
                                        }
                                    }
                                }
                                cJSON_Delete(root);
                            }
                        }
                    }
                    break;
                    
                case 0x9:  // Ping
                    {
                        // 发送 Pong
                        const char* pong = "pong";
                        httpd_resp_send(req, pong, strlen(pong));
                    }
                    break;
            }
        }
        
        free(buf);
    }

    return ESP_OK;
}

// HTTP 请求处理回调
esp_err_t LocalWebsocketServer::HandleHttpRequest(httpd_req_t *req) {
    const char* resp_str = "Welcome to ESP32 WebSocket Server";
    httpd_resp_send(req, resp_str, strlen(resp_str));
    return ESP_OK;
}

// 启动服务器
bool LocalWebsocketServer::Start(uint16_t port) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = port;
    config.max_open_sockets = 4;
    config.stack_size = 8192;
    config.lru_purge_enable = true;
    config.recv_wait_timeout = WS_PING_TIMEOUT_MS / 1000;  // 设置接收超时时间

    httpd_uri_t ws = {
        .uri        = "/ws",
        .method     = HTTP_GET,
        .handler    = HandleWebSocket,
        .user_ctx   = nullptr
    };

    httpd_uri_t uri = {
        .uri        = "/",
        .method     = HTTP_GET,
        .handler    = HandleHttpRequest,
        .user_ctx   = nullptr
    };

    if (httpd_start(&server_, &config) == ESP_OK) {
        httpd_register_uri_handler(server_, &ws);
        httpd_register_uri_handler(server_, &uri);
        ESP_LOGI(TAG, "WebSocket server started on port %d", port);
        return true;
    }

    ESP_LOGE(TAG, "Failed to start WebSocket server");
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