#include "local_websocket_server.h"
#include "settings.h"
#include "wifi_station.h"
#include "system_info.h"
#include "board.h"
#include "application.h"
#include "audio_codecs/audio_codec.h"

#include <esp_log.h>
#include <esp_http_server.h>
#include <esp_wifi.h>
#include <cstring>
#include <cJSON.h>
#include <mbedtls/base64.h>
#include <mbedtls/sha1.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>

#define TAG "WebSocketServer"
#define WS_PING_INTERVAL_MS 30000 // 30秒发送一次 ping
#define WS_PING_TIMEOUT_MS 120000 // 120秒没有响应则断开连接

// 添加 WebSocket 帧解析相关的结构和常量
#define WS_FIN 0x80
#define WS_OPCODE_MASK 0x0F
#define WS_MASK 0x80
#define WS_LENGTH_MASK 0x7F

#define WS_OPCODE_CONTINUATION 0x0
#define WS_OPCODE_TEXT 0x1
#define WS_OPCODE_BINARY 0x2
#define WS_OPCODE_CLOSE 0x8
#define WS_OPCODE_PING 0x9
#define WS_OPCODE_PONG 0xA

struct ws_frame_info_t
{
    bool fin;
    uint8_t opcode;
    bool mask;
    uint64_t payload_length;
    uint8_t mask_key[4];
};

// 添加函数前向声明
static esp_err_t SendWebSocketMessage(int sock, const char *message, size_t len);
static esp_err_t HandleJsonMessage(int sock, const char *message);

// 生成 WebSocket 接受密钥
static void GenerateAcceptKey(const char *client_key, char *accept_key)
{
    const char *magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    unsigned char sha1_hash[20];
    char combined_key[128];

    // 组合客户端密钥和魔术字符串
    snprintf(combined_key, sizeof(combined_key), "%s%s", client_key, magic);

    // 计算 SHA1
    mbedtls_sha1_context sha1_ctx;
    mbedtls_sha1_init(&sha1_ctx);
    mbedtls_sha1_starts(&sha1_ctx);
    mbedtls_sha1_update(&sha1_ctx, (const unsigned char *)combined_key, strlen(combined_key));
    mbedtls_sha1_finish(&sha1_ctx, sha1_hash);
    mbedtls_sha1_free(&sha1_ctx);

    // Base64 编码
    size_t out_len;
    mbedtls_base64_encode((unsigned char *)accept_key, 32, &out_len, sha1_hash, 20);
    accept_key[out_len] = '\0';
}

// 添加 WebSocket 帧处理函数
static esp_err_t HandleWebSocketFrame(httpd_req_t *req)
{
    uint8_t buf[1024];
    ws_frame_info_t frame = {};

    // 设置socket为非阻塞模式
    int sock = httpd_req_to_sockfd(req);
    if (sock < 0)
    {
        ESP_LOGE(TAG, "Failed to get socket fd");
        return ESP_FAIL;
    }

    // 设置更长的接收超时时间
    struct timeval tv;
    tv.tv_sec = 30; // 30秒超时
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
    {
        ESP_LOGE(TAG, "Failed to set socket receive timeout");
        return ESP_FAIL;
    }

    // 读取前两个字节以获取基本信息
    int ret = recv(sock, buf, 2, 0);
    ESP_LOGI(TAG, "Read header bytes: %d", ret);
    if (ret == -1)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            ESP_LOGW(TAG, "Socket timeout, continuing...");
            return ESP_OK; // 超时时继续等待
        }
        ESP_LOGE(TAG, "Failed to read frame header: errno %d", errno);
        return ESP_FAIL;
    }
    if (ret == 0)
    {
        ESP_LOGI(TAG, "Client closed connection");
        return ESP_FAIL;
    }

    frame.fin = (buf[0] & WS_FIN) != 0;
    frame.opcode = buf[0] & WS_OPCODE_MASK;
    frame.mask = (buf[1] & WS_MASK) != 0;
    frame.payload_length = buf[1] & WS_LENGTH_MASK;

    ESP_LOGI(TAG, "Frame info - FIN: %d, Opcode: 0x%x, MASK: %d, Length: %llu",
             frame.fin, frame.opcode, frame.mask, frame.payload_length);

    // 处理扩展长度
    if (frame.payload_length == 126)
    {
        ret = recv(sock, buf + 2, 2, 0);
        if (ret <= 0)
        {
            ESP_LOGE(TAG, "Failed to read extended length (16-bit)");
            return ESP_FAIL;
        }
        frame.payload_length = (buf[2] << 8) | buf[3];
        ESP_LOGI(TAG, "Extended length (16-bit): %llu", frame.payload_length);
    }
    else if (frame.payload_length == 127)
    {
        ret = recv(sock, buf + 2, 8, 0);
        if (ret <= 0)
        {
            ESP_LOGE(TAG, "Failed to read extended length (64-bit)");
            return ESP_FAIL;
        }
        frame.payload_length = 0;
        for (int i = 0; i < 8; i++)
        {
            frame.payload_length = (frame.payload_length << 8) | buf[2 + i];
        }
        ESP_LOGI(TAG, "Extended length (64-bit): %llu", frame.payload_length);
    }

    // 读取掩码
    if (frame.mask)
    {
        ret = recv(sock, frame.mask_key, 4, 0);
        if (ret <= 0)
        {
            ESP_LOGE(TAG, "Failed to read mask key");
            return ESP_FAIL;
        }
        ESP_LOGI(TAG, "Mask key: %02x %02x %02x %02x",
                 frame.mask_key[0], frame.mask_key[1],
                 frame.mask_key[2], frame.mask_key[3]);
    }

    // 读取和处理负载数据
    if (frame.payload_length > 0)
    {
        if (frame.payload_length > sizeof(buf))
        {
            ESP_LOGE(TAG, "Payload too large: %llu", frame.payload_length);
            return ESP_FAIL;
        }

        size_t remaining = frame.payload_length;
        size_t total_read = 0;

        while (remaining > 0)
        {
            size_t to_read = (remaining > sizeof(buf)) ? sizeof(buf) : remaining;
            ret = recv(sock, buf + total_read, to_read, 0);
            ESP_LOGI(TAG, "Read payload bytes: %d of %zu", ret, to_read);

            if (ret <= 0)
            {
                ESP_LOGE(TAG, "Failed to read payload data");
                return ESP_FAIL;
            }

            total_read += ret;
            remaining -= ret;
        }

        // 解除掩码
        if (frame.mask)
        {
            for (size_t i = 0; i < total_read; i++)
            {
                buf[i] ^= frame.mask_key[i % 4];
            }
        }

        // 确保字符串结束
        buf[total_read] = '\0';

        // 处理数据
        switch (frame.opcode)
        {
        case WS_OPCODE_TEXT:
        {
            ESP_LOGI(TAG, "Received text message: %s", buf);
            // 确保字符串正确终止
            buf[total_read] = '\0';
            // 处理 JSON 消息
            if (HandleJsonMessage(sock, (char *)buf) != ESP_OK)
            {
                ESP_LOGE(TAG, "Failed to handle JSON message");
            }
            break;
        }

        case WS_OPCODE_BINARY:
            ESP_LOGI(TAG, "Received binary message (%zu bytes)", total_read);
            break;

        case WS_OPCODE_PING:
        {
            ESP_LOGI(TAG, "Received WebSocket ping frame, sending pong");
            uint8_t pong[2] = {(uint8_t)(WS_FIN | WS_OPCODE_PONG), 0};
            send(sock, pong, 2, 0);
            break;
        }

        case WS_OPCODE_PONG:
            ESP_LOGI(TAG, "Received WebSocket pong frame");
            break;

        case WS_OPCODE_CLOSE:
            ESP_LOGI(TAG, "Received close frame");
            return ESP_FAIL;

        default:
            ESP_LOGW(TAG, "Unknown opcode: 0x%x", frame.opcode);
            break;
        }
    }

    return ESP_OK;
}

// 修改 HandleWebSocket 函数
esp_err_t LocalWebsocketServer::HandleWebSocket(httpd_req_t *req)
{
    ESP_LOGI(TAG, "\n=== WebSocket handler ===");
    ESP_LOGI(TAG, "URI: %s", req->uri);
    ESP_LOGI(TAG, "Method: %s", (req->method == HTTP_GET) ? "GET" : "OTHER");

    // 打印所有头部
    const char *headers[] = {
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
        "Origin"};

    bool is_websocket = false;
    char ws_key[64] = {0};

    for (const char *header : headers)
    {
        size_t len = httpd_req_get_hdr_value_len(req, header);
        if (len > 0)
        {
            char *value = (char *)malloc(len + 1);
            if (value)
            {
                if (httpd_req_get_hdr_value_str(req, header, value, len + 1) == ESP_OK)
                {
                    ESP_LOGI(TAG, "Header %s: %s", header, value);

                    if (strcmp(header, "Upgrade") == 0 &&
                        strcasecmp(value, "websocket") == 0)
                    {
                        is_websocket = true;
                    }

                    if (strcmp(header, "Sec-WebSocket-Key") == 0)
                    {
                        strncpy(ws_key, value, sizeof(ws_key) - 1);
                    }
                }
                free(value);
            }
        }
    }

    if (req->method == HTTP_GET && is_websocket && strlen(ws_key) > 0)
    {
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

        // 握手成功后，进入帧处理循环
        while (true)
        {
            esp_err_t ret = HandleWebSocketFrame(req);
            if (ret == ESP_FAIL)
            {
                ESP_LOGI(TAG, "WebSocket connection closed");
                break;
            }
            // 添加短暂延时，避免CPU占用过高
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        return ESP_OK;
    }

    ESP_LOGI(TAG, "Invalid WebSocket request");
    httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid WebSocket request");
    return ESP_FAIL;
}

// 通用请求处理函数
static esp_err_t HandleAllRequests(httpd_req_t *req)
{
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

// 添加发送 WebSocket 消息的辅助函数
static esp_err_t SendWebSocketMessage(int sock, const char *message, size_t len)
{
    ESP_LOGI(TAG, "Sending message: %s", message); // 添加日志

    // 计算帧头大小
    size_t header_len = 2;
    if (len > 125)
    {
        header_len += (len > 65535) ? 8 : 2;
    }

    // 分配帧缓冲区
    uint8_t *frame = (uint8_t *)malloc(header_len + len);
    if (!frame)
    {
        ESP_LOGE(TAG, "Failed to allocate frame buffer");
        return ESP_FAIL;
    }

    // 设置帧头
    frame[0] = WS_FIN | WS_OPCODE_TEXT;

    // 设置长度
    if (len <= 125)
    {
        frame[1] = len;
    }
    else if (len <= 65535)
    {
        frame[1] = 126;
        frame[2] = (len >> 8) & 0xFF;
        frame[3] = len & 0xFF;
    }
    else
    {
        frame[1] = 127;
        for (int i = 0; i < 8; i++)
        {
            frame[2 + i] = (len >> ((7 - i) * 8)) & 0xFF;
        }
    }

    // 复制消息数据
    memcpy(frame + header_len, message, len);

    // 发送帧
    ESP_LOGI(TAG, "Sending frame with length: %d", header_len + len); // 添加日志
    int ret = send(sock, frame, header_len + len, 0);
    if (ret < 0)
    {
        ESP_LOGE(TAG, "Failed to send WebSocket message: errno %d", errno);
    }
    else
    {
        ESP_LOGI(TAG, "Successfully sent %d bytes", ret);
    }

    free(frame);
    return (ret < 0) ? ESP_FAIL : ESP_OK;
}

// 添加一个辅助函数来检查键的长度
bool IsValidNvsKey(const char *key)
{
    return strlen(key) <= 15; // NVS 键的最大长度是 15 字符
}

// 处理 JSON 消息
static esp_err_t HandleJsonMessage(int sock, const char *message)
{
    ESP_LOGI(TAG, "Processing JSON message: %s", message);

    // 处理简单的 ping 消息
    if (strcmp(message, "ping") == 0)
    {
        const char *pong_response = "pong";
        return SendWebSocketMessage(sock, pong_response, strlen(pong_response));
    }

    // 解析 JSON 消息
    cJSON *root = cJSON_Parse(message);
    if (!root)
    {
        ESP_LOGE(TAG, "Failed to parse JSON message: %s", cJSON_GetErrorPtr());
        return ESP_FAIL;
    }

    cJSON *type = cJSON_GetObjectItem(root, "type");
    if (!type || !cJSON_IsString(type))
    {
        ESP_LOGE(TAG, "Missing or invalid 'type' field");
        cJSON_Delete(root);
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Message type: %s", type->valuestring);

    if (strcmp(type->valuestring, "get_config") == 0)
    {
        // 创建响应
        cJSON *response = cJSON_CreateObject();
        if (!response)
        {
            ESP_LOGE(TAG, "Failed to create response object");
            cJSON_Delete(root);
            return ESP_FAIL;
        }

        cJSON_AddStringToObject(response, "type", "get_config");

        // 添加配置数据
        cJSON *config = cJSON_CreateObject();
        if (!config)
        {
            ESP_LOGE(TAG, "Failed to create config object");
            cJSON_Delete(response);
            cJSON_Delete(root);
            return ESP_FAIL;
        }

        // 从 Settings 获取 WiFi 配置
        Settings wifi_settings("wifi");
        cJSON_AddStringToObject(config, "ssid", wifi_settings.GetString("ssid", "").c_str());
        cJSON_AddStringToObject(config, "password", wifi_settings.GetString("password", "").c_str());
        cJSON_AddStringToObject(config, "hostname", wifi_settings.GetString("hostname", "xiaozhi").c_str());

        // 添加 WiFi 连接状态
        cJSON_AddBoolToObject(config, "wifi_connected", WifiStation::GetInstance().IsConnected());

        // 添加系统信息
        cJSON_AddStringToObject(config, "mac_address", SystemInfo::GetMacAddress().c_str());
        cJSON_AddStringToObject(config, "chip_model", SystemInfo::GetChipModelName().c_str());
        cJSON_AddNumberToObject(config, "free_heap", SystemInfo::GetFreeHeapSize());

        // 添加自定义配置
        Settings custom_settings("custom");
        cJSON *custom_config = cJSON_CreateObject();
        if (custom_config)
        {
            // 获取实际设备音量
            auto codec = Board::GetInstance().GetAudioCodec();
            if (codec)
            {
                try
                {
                    int current_volume = codec->output_volume();
                    cJSON_AddNumberToObject(custom_config, "volume", current_volume);
                    ESP_LOGI(TAG, "Current device volume: %d", current_volume);
                }
                catch (const std::exception &e)
                {
                    ESP_LOGW(TAG, "Failed to get device volume: %s", e.what());
                    // 如果获取失败，尝试从配置中读取
                    int saved_volume = custom_settings.GetInt("volume", 50);
                    cJSON_AddNumberToObject(custom_config, "volume", saved_volume);
                }
            }

            // 定义所有可能的键
            const char *string_keys[] = {
                "welcomeWord", "sleepWord", "waitWord", "roleWord",
                "wakeupWord", "failWord", "voice", "botId", "apiToken"};
            const char *int_keys[] = {
                "emotion", "language", "speed", "tone", "model"};

            // 获取字符串类型的配置
            for (const char *key : string_keys)
            {
                std::string value = custom_settings.GetString(key, "");
                cJSON_AddStringToObject(custom_config, key, value.c_str());
                ESP_LOGI(TAG, "Read custom string setting: %s = %s", key, value.c_str());
            }

            // 获取整数类型的配置
            for (const char *key : int_keys)
            {
                int value = custom_settings.GetInt(key, 0);
                cJSON_AddNumberToObject(custom_config, key, value);
                ESP_LOGI(TAG, "Read custom int setting: %s = %d", key, value);
            }

            // 将 custom_config 添加到 config 对象中
            cJSON_AddItemToObject(config, "custom", custom_config);
        }

        // 添加配置对象到响应
        cJSON_AddItemToObject(response, "config", config);

        // 转换为字符串并发送
        char *json_str = cJSON_PrintUnformatted(response);
        if (json_str)
        {
            ESP_LOGI(TAG, "Sending config response: %s", json_str);
            esp_err_t ret = SendWebSocketMessage(sock, json_str, strlen(json_str));
            free(json_str);
            cJSON_Delete(response);
            cJSON_Delete(root);
            return ret;
        }

        ESP_LOGE(TAG, "Failed to convert response to string");
        cJSON_Delete(response);
    }
    else if (strcmp(type->valuestring, "set_config") == 0)
    {
        // 处理set_config消息 - 添加自定义配置保存功能
        cJSON *data = cJSON_GetObjectItem(root, "data");
        if (!data || !cJSON_IsObject(data))
        {
            ESP_LOGE(TAG, "Missing or invalid 'data' field");
            cJSON_Delete(root);
            return ESP_FAIL;
        }

        // 处理WiFi配置
        cJSON *wifi = cJSON_GetObjectItem(data, "wifi");
        if (wifi && cJSON_IsObject(wifi))
        {
            Settings wifi_settings("wifi", true);

            cJSON *ssid = cJSON_GetObjectItem(wifi, "ssid");
            if (ssid && cJSON_IsString(ssid))
            {
                wifi_settings.SetString("ssid", ssid->valuestring);
                ESP_LOGI(TAG, "Saved WiFi SSID: %s", ssid->valuestring);
            }

            cJSON *password = cJSON_GetObjectItem(wifi, "password");
            if (password && cJSON_IsString(password))
            {
                wifi_settings.SetString("password", password->valuestring);
                ESP_LOGI(TAG, "Saved WiFi password");
            }

            cJSON *hostname = cJSON_GetObjectItem(wifi, "hostname");
            if (hostname && cJSON_IsString(hostname))
            {
                wifi_settings.SetString("hostname", hostname->valuestring);
                ESP_LOGI(TAG, "Saved hostname: %s", hostname->valuestring);
            }
        }

        // 处理自定义配置
        cJSON *custom = cJSON_GetObjectItem(data, "custom");
        if (custom && cJSON_IsObject(custom))
        {
            Settings custom_settings("custom", true);

            // 遍历所有自定义配置项并保存
            cJSON *item = NULL;
            cJSON_ArrayForEach(item, custom)
            {
                // 添加键长度检查
                if (!IsValidNvsKey(item->string))
                {
                    ESP_LOGW(TAG, "Key '%s' is too long (max 15 chars), skipping", item->string);
                    continue;
                }

                try
                {
                    // 特殊处理音量设置
                    if (strcmp(item->string, "volume") == 0 && cJSON_IsNumber(item))
                    {
                        int volume = item->valueint;
                        // 确保音量在有效范围内
                        if (volume < 0)
                            volume = 0;
                        if (volume > 100)
                            volume = 100;

                        // 设置设备音量
                        auto codec = Board::GetInstance().GetAudioCodec();
                        if (codec)
                        {
                            try
                            {
                                codec->SetOutputVolume(volume);
                                ESP_LOGI(TAG, "Set device volume to: %d", volume);
                                // 成功设置后保存到配置中
                                custom_settings.SetInt(item->string, volume);
                            }
                            catch (const std::exception &e)
                            {
                                ESP_LOGW(TAG, "Failed to set device volume: %s", e.what());
                            }
                        }
                    }
                    else
                    {
                        // 其他配置项正常保存
                        if (cJSON_IsString(item))
                        {
                            custom_settings.SetString(item->string, item->valuestring);
                            ESP_LOGI(TAG, "Saved custom string setting: %s = %s", item->string, item->valuestring);
                        }
                        else if (cJSON_IsNumber(item))
                        {
                            custom_settings.SetInt(item->string, item->valueint);
                            ESP_LOGI(TAG, "Saved custom int setting: %s = %d", item->string, item->valueint);
                        }
                        else if (cJSON_IsBool(item))
                        {
                            custom_settings.SetBool(item->string, cJSON_IsTrue(item));
                            ESP_LOGI(TAG, "Saved custom bool setting: %s = %d", item->string, cJSON_IsTrue(item));
                        }
                    }
                }
                catch (const std::exception &e)
                {
                    ESP_LOGW(TAG, "Failed to save setting '%s': %s", item->string, e.what());
                }
            }
        }

        // 发送成功响应
        cJSON *response = cJSON_CreateObject();
        if (response)
        {
            cJSON_AddStringToObject(response, "type", "set_config_response");
            cJSON_AddBoolToObject(response, "success", true);

            char *json_str = cJSON_PrintUnformatted(response);
            if (json_str)
            {
                esp_err_t ret = SendWebSocketMessage(sock, json_str, strlen(json_str));
                free(json_str);
                cJSON_Delete(response);
                cJSON_Delete(root);
                return ret;
            }
            cJSON_Delete(response);
        }
    }
    else if (strcmp(type->valuestring, "get_custom_config") == 0)
    {
        // 添加获取自定义配置的处理
        Settings custom_settings("custom");

        // 创建响应
        cJSON *response = cJSON_CreateObject();
        if (!response)
        {
            ESP_LOGE(TAG, "Failed to create response object");
            cJSON_Delete(root);
            return ESP_FAIL;
        }

        cJSON_AddStringToObject(response, "type", "get_custom_config");

        // 添加所有自定义配置项
        cJSON *config = cJSON_CreateObject();
        if (!config)
        {
            ESP_LOGE(TAG, "Failed to create config object");
            cJSON_Delete(response);
            cJSON_Delete(root);
            return ESP_FAIL;
        }

        // 获取实际设备音量
        auto codec = Board::GetInstance().GetAudioCodec();
        if (codec)
        {
            try
            {
                int current_volume = codec->output_volume();
                cJSON_AddNumberToObject(config, "volume", current_volume);
                ESP_LOGI(TAG, "Current device volume: %d", current_volume);
            }
            catch (const std::exception &e)
            {
                ESP_LOGW(TAG, "Failed to get device volume: %s", e.what());
                // 如果获取失败，尝试从配置中读取
                int saved_volume = custom_settings.GetInt("volume", 50);
                cJSON_AddNumberToObject(config, "volume", saved_volume);
            }
        }

        // 动态获取所有自定义配置
        std::vector<std::string> keys = custom_settings.GetAllKeys();
        for (const auto &key : keys)
        {
            // 跳过 volume，因为我们已经从设备读取了实际值
            if (key == "volume")
                continue;

            if (custom_settings.Contains(key))
            {
                if (custom_settings.IsString(key))
                {
                    cJSON_AddStringToObject(config, key.c_str(), custom_settings.GetString(key, "").c_str());
                }
                else if (custom_settings.IsInt(key))
                {
                    cJSON_AddNumberToObject(config, key.c_str(), custom_settings.GetInt(key, 0));
                }
                else if (custom_settings.IsBool(key))
                {
                    cJSON_AddBoolToObject(config, key.c_str(), custom_settings.GetBool(key, false));
                }
            }
        }

        // 添加自定义配置到响应
        cJSON_AddItemToObject(response, "config", config);

        // 转换为字符串并发送
        char *json_str = cJSON_PrintUnformatted(response);
        if (json_str)
        {
            ESP_LOGI(TAG, "Sending custom config response: %s", json_str);
            esp_err_t ret = SendWebSocketMessage(sock, json_str, strlen(json_str));
            free(json_str);
            cJSON_Delete(response);
            cJSON_Delete(root);
            return ret;
        }

        ESP_LOGE(TAG, "Failed to convert response to string");
        cJSON_Delete(response);
    }
    else if (strcmp(type->valuestring, "ping") == 0)
    {
        // 处理 JSON 格式的 ping
        cJSON *response = cJSON_CreateObject();
        if (response)
        {
            cJSON_AddStringToObject(response, "type", "pong");
            char *json_str = cJSON_PrintUnformatted(response);
            if (json_str)
            {
                esp_err_t ret = SendWebSocketMessage(sock, json_str, strlen(json_str));
                free(json_str);
                cJSON_Delete(response);
                cJSON_Delete(root);
                return ret;
            }
            cJSON_Delete(response);
        }
    }
    else if (strcmp(type->valuestring, "reboot") == 0)
    {
        // 创建响应
        cJSON *response = cJSON_CreateObject();
        if (response)
        {
            cJSON_AddStringToObject(response, "type", "reboot_response");
            cJSON_AddBoolToObject(response, "success", true);

            // 发送响应
            char *json_str = cJSON_PrintUnformatted(response);
            if (json_str)
            {
                // 发送响应并检查结果
                if (SendWebSocketMessage(sock, json_str, strlen(json_str)) == ESP_OK)
                {
                    free(json_str);
                    cJSON_Delete(response);
                    cJSON_Delete(root);

                    // 延迟一小段时间确保响应发送完成
                    vTaskDelay(pdMS_TO_TICKS(500));

                    // 创建一个独立的任务来执行重启
                    xTaskCreate([](void *)
                                {
                        // 停止 WebSocket 服务器
                        LocalWebsocketServer::GetInstance().Stop();
                        
                        // 停止 WiFi
                        WifiStation::GetInstance().Stop();
                        
                        // 延迟以确保所有资源都被正确释放
                        vTaskDelay(pdMS_TO_TICKS(1000));
                        
                        // 重启设备
                        esp_restart();
                        
                        vTaskDelete(NULL); },
                                "reboot_task", 4096, nullptr, 5, nullptr);

                    return ESP_OK;
                }
                free(json_str);
            }
            cJSON_Delete(response);
        }
        cJSON_Delete(root);
        return ESP_FAIL;
    }
    else
    {
        ESP_LOGW(TAG, "Unknown message type: %s", type->valuestring);
    }

    cJSON_Delete(root);
    return ESP_OK;
}

// 添加 ping 处理函数
static esp_err_t HandlePing(httpd_req_t *req)
{
    ESP_LOGI(TAG, "Received ping request");

    // 设置响应头
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_set_hdr(req, "Access-Control-Allow-Origin", "*");

    // 发送 "pong" 响应
    const char *response = "pong";
    esp_err_t ret = httpd_resp_send(req, response, strlen(response));

    if (ret != ESP_OK)
    {
        ESP_LOGE(TAG, "Failed to send ping response");
    }
    return ret;
}

// 启动服务器
bool LocalWebsocketServer::Start(uint16_t port)
{
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = port;
    config.lru_purge_enable = true;
    config.max_uri_handlers = 8;
    config.max_resp_headers = 8;
    config.recv_wait_timeout = 30; // 增加接收超时时间到30秒
    config.send_wait_timeout = 30; // 增加发送超时时间到30秒
    config.max_open_sockets = 3;   // 增加最大连接数
    config.backlog_conn = 5;       // 增加等待队列
    config.core_id = 0;            // 指定核心
    config.stack_size = 8192;      // 增加栈大小

    ESP_LOGI(TAG, "Starting server with config:");
    ESP_LOGI(TAG, "Port: %d, Max handlers: %d, Stack: %d, Timeouts: %d/%d",
             config.server_port, config.max_uri_handlers,
             config.stack_size, config.recv_wait_timeout,
             config.send_wait_timeout);

    if (httpd_start(&server_, &config) == ESP_OK)
    {
        // 注册 ping 处理程序
        httpd_uri_t ping = {
            .uri = "/ping",
            .method = HTTP_GET,
            .handler = HandlePing,
            .user_ctx = nullptr};

        ESP_LOGI(TAG, "Registering ping handler");
        esp_err_t ret = httpd_register_uri_handler(server_, &ping);
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to register ping handler: %d", ret);
        }

        // 注册 WebSocket 处理程序
        httpd_uri_t ws = {
            .uri = "/ws",
            .method = HTTP_GET,
            .handler = HandleWebSocket,
            .user_ctx = nullptr};

        ESP_LOGI(TAG, "Registering WebSocket handler");
        ret = httpd_register_uri_handler(server_, &ws);
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to register WebSocket handler: %d", ret);
            return false;
        }

        // 注册一个通用处理程序来捕获所有请求
        httpd_uri_t catch_all = {
            .uri = "/*",
            .method = HTTP_GET,
            .handler = HandleAllRequests,
            .user_ctx = nullptr};

        ESP_LOGI(TAG, "Registering catch-all handler");
        ret = httpd_register_uri_handler(server_, &catch_all);
        if (ret != ESP_OK)
        {
            ESP_LOGE(TAG, "Failed to register catch-all handler: %d", ret);
        }

        ESP_LOGI(TAG, "Server started successfully");
        return true;
    }

    ESP_LOGE(TAG, "Failed to start server");
    return false;
}

// 停止服务器
void LocalWebsocketServer::Stop()
{
    if (server_)
    {
        httpd_stop(server_);
        server_ = nullptr;
    }
}

// 析构函数
LocalWebsocketServer::~LocalWebsocketServer()
{
    Stop();
}

// 获取单例实例
LocalWebsocketServer &LocalWebsocketServer::GetInstance()
{
    static LocalWebsocketServer instance;
    return instance;
}