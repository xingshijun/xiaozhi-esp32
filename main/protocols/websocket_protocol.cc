#include "websocket_protocol.h"
#include "board.h"
#include "system_info.h"
#include "application.h"
#include "settings.h"

#include <cstring>
#include <cJSON.h>
#include <esp_log.h>
#include <arpa/inet.h>
#include "assets/lang_config.h"

#define TAG "WS"

WebsocketProtocol::WebsocketProtocol() {
    event_group_handle_ = xEventGroupCreate();
}

WebsocketProtocol::~WebsocketProtocol() {
    if (websocket_ != nullptr) {
        delete websocket_;
    }
    vEventGroupDelete(event_group_handle_);
}

void WebsocketProtocol::Start() {
}

void WebsocketProtocol::SendAudio(const std::vector<uint8_t>& data) {
    if (websocket_ == nullptr) {
        return;
    }

    websocket_->Send(data.data(), data.size(), true);
}

void WebsocketProtocol::SendText(const std::string& text) {
    if (websocket_ == nullptr) {
        return;
    }

    websocket_->Send(text);
}

bool WebsocketProtocol::IsAudioChannelOpened() const {
    return websocket_ != nullptr && websocket_->IsConnected();
}

void WebsocketProtocol::CloseAudioChannel() {
    if (websocket_ != nullptr) {
        delete websocket_;
        websocket_ = nullptr;
    }
}

bool WebsocketProtocol::OpenAudioChannel() {
    if (websocket_ != nullptr) {
        delete websocket_;
    }

    std::string url = CONFIG_WEBSOCKET_URL;
    std::string token = "Bearer " + std::string(CONFIG_WEBSOCKET_ACCESS_TOKEN);
    websocket_ = Board::GetInstance().CreateWebSocket();
    websocket_->SetHeader("Authorization", token.c_str());
    websocket_->SetHeader("Protocol-Version", "1");
    websocket_->SetHeader("Device-Id", SystemInfo::GetMacAddress().c_str());
    websocket_->SetHeader("Client-Id", Board::GetInstance().GetUuid().c_str());

    websocket_->OnData([this](const char* data, size_t len, bool binary) {
        if (binary) {
            if (on_incoming_audio_ != nullptr) {
                on_incoming_audio_(std::vector<uint8_t>((uint8_t*)data, (uint8_t*)data + len));
            }
        } else {
            // Parse JSON data
            auto root = cJSON_Parse(data);
            auto type = cJSON_GetObjectItem(root, "type");
            if (type != NULL) {
                if (strcmp(type->valuestring, "hello") == 0) {
                    ParseServerHello(root);
                } else {
                    if (on_incoming_json_ != nullptr) {
                        on_incoming_json_(root);
                    }
                }
            } else {
                ESP_LOGE(TAG, "Missing message type, data: %s", data);
            }
            cJSON_Delete(root);
        }
    });

    websocket_->OnDisconnected([this]() {
        ESP_LOGI(TAG, "Websocket disconnected");
        if (on_audio_channel_closed_ != nullptr) {
            on_audio_channel_closed_();
        }
    });

    if (!websocket_->Connect(url.c_str())) {
        ESP_LOGE(TAG, "Failed to connect to websocket server");
        if (on_network_error_ != nullptr) {
            on_network_error_(Lang::Strings::SERVER_NOT_FOUND);
        }
        return false;
    }

    // Send hello message to describe the client
    // 构建hello消息，添加custom配置信息
    cJSON* root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "type", "hello");
    cJSON_AddNumberToObject(root, "version", 1);
    cJSON_AddStringToObject(root, "transport", "websocket");
    
    // 添加音频参数
    cJSON* audio_params = cJSON_CreateObject();
    cJSON_AddStringToObject(audio_params, "format", "opus");
    cJSON_AddNumberToObject(audio_params, "sample_rate", 16000);
    cJSON_AddNumberToObject(audio_params, "channels", 1);
    cJSON_AddNumberToObject(audio_params, "frame_duration", OPUS_FRAME_DURATION_MS);
    cJSON_AddItemToObject(root, "audio_params", audio_params);
    
    // 添加自定义配置
    Settings custom_settings("custom");
    std::vector<std::string> keys = custom_settings.GetAllKeys();
    if (!keys.empty()) {
        cJSON* custom_config = cJSON_CreateObject();
        
        for (const auto& key : keys) {
            if (custom_settings.IsString(key)) {
                cJSON_AddStringToObject(custom_config, key.c_str(), 
                                        custom_settings.GetString(key, "").c_str());
            } else if (custom_settings.IsInt(key)) {
                cJSON_AddNumberToObject(custom_config, key.c_str(), 
                                        custom_settings.GetInt(key, 0));
            } else if (custom_settings.IsBool(key)) {
                cJSON_AddBoolToObject(custom_config, key.c_str(), 
                                      custom_settings.GetBool(key, false));
            }
        }
        
        cJSON_AddItemToObject(root, "custom_config", custom_config);
    }
    
    // 转换为字符串并发送
    char* json_str = cJSON_PrintUnformatted(root);
    if (json_str) {
        ESP_LOGI(TAG, "Sending hello with custom config: %s", json_str);
        websocket_->Send(json_str);
        free(json_str);
    } else {
        // 使用简单的字符串作为备用
        std::string message = "{";
        message += "\"type\":\"hello\",";
        message += "\"version\": 1,";
        message += "\"transport\":\"websocket\",";
        message += "\"audio_params\":{";
        message += "\"format\":\"opus\", \"sample_rate\":16000, \"channels\":1, \"frame_duration\":" + std::to_string(OPUS_FRAME_DURATION_MS);
        message += "}}";
        websocket_->Send(message);
    }
    
    cJSON_Delete(root);

    // Wait for server hello
    EventBits_t bits = xEventGroupWaitBits(event_group_handle_, WEBSOCKET_PROTOCOL_SERVER_HELLO_EVENT, pdTRUE, pdFALSE, pdMS_TO_TICKS(10000));
    if (!(bits & WEBSOCKET_PROTOCOL_SERVER_HELLO_EVENT)) {
        ESP_LOGE(TAG, "Failed to receive server hello");
        if (on_network_error_ != nullptr) {
            on_network_error_(Lang::Strings::SERVER_TIMEOUT);
        }
        return false;
    }

    if (on_audio_channel_opened_ != nullptr) {
        on_audio_channel_opened_();
    }

    return true;
}

void WebsocketProtocol::ParseServerHello(const cJSON* root) {
    auto transport = cJSON_GetObjectItem(root, "transport");
    if (transport == nullptr || strcmp(transport->valuestring, "websocket") != 0) {
        ESP_LOGE(TAG, "Unsupported transport: %s", transport->valuestring);
        return;
    }

    auto audio_params = cJSON_GetObjectItem(root, "audio_params");
    if (audio_params != NULL) {
        auto sample_rate = cJSON_GetObjectItem(audio_params, "sample_rate");
        if (sample_rate != NULL) {
            server_sample_rate_ = sample_rate->valueint;
        }
    }

    xEventGroupSetBits(event_group_handle_, WEBSOCKET_PROTOCOL_SERVER_HELLO_EVENT);
}
