#include "wifi_board.h"
#include "audio_codecs/no_audio_codec.h"
#include "display/ssd1306_display.h"
#include "system_reset.h"
#include "application.h"
#include "button.h"
#include "config.h"
#include "iot/thing_manager.h"
#include "led/single_led.h"
#include "local_websocket_server.h"
#include "settings.h"
#include "system_info.h"

#include <wifi_station.h>
#include <esp_log.h>
#include <driver/i2c_master.h>
#include <esp_wifi.h>
#include <freertos/event_groups.h>

#define TAG "CompactWifiBoard"

LV_FONT_DECLARE(font_puhui_14_1);
LV_FONT_DECLARE(font_awesome_14_1);

class CompactWifiBoard : public WifiBoard {
private:
    i2c_master_bus_handle_t display_i2c_bus_;
    Button boot_button_;
    Button touch_button_;
    Button volume_up_button_;
    Button volume_down_button_;

    void InitializeDisplayI2c() {
        i2c_master_bus_config_t bus_config = {
            .i2c_port = (i2c_port_t)0,
            .sda_io_num = DISPLAY_SDA_PIN,
            .scl_io_num = DISPLAY_SCL_PIN,
            .clk_source = I2C_CLK_SRC_DEFAULT,
            .glitch_ignore_cnt = 7,
            .intr_priority = 0,
            .trans_queue_depth = 0,
            .flags = {
                .enable_internal_pullup = 1,
            },
        };
        ESP_ERROR_CHECK(i2c_new_master_bus(&bus_config, &display_i2c_bus_));
    }

    void InitializeButtons() {
        boot_button_.OnClick([this]() {
            auto& app = Application::GetInstance();
            if (app.GetDeviceState() == kDeviceStateStarting && !WifiStation::GetInstance().IsConnected()) {
                ResetWifiConfiguration();
            }
            app.ToggleChatState();
        });
        touch_button_.OnPressDown([this]() {
            Application::GetInstance().StartListening();
        });
        touch_button_.OnPressUp([this]() {
            Application::GetInstance().StopListening();
        });

        volume_up_button_.OnClick([this]() {
            auto codec = GetAudioCodec();
            auto volume = codec->output_volume() + 10;
            if (volume > 100) {
                volume = 100;
            }
            codec->SetOutputVolume(volume);
            GetDisplay()->ShowNotification("音量 " + std::to_string(volume));
        });

        volume_up_button_.OnLongPress([this]() {
            GetAudioCodec()->SetOutputVolume(100);
            GetDisplay()->ShowNotification("最大音量");
        });

        volume_down_button_.OnClick([this]() {
            auto codec = GetAudioCodec();
            auto volume = codec->output_volume() - 10;
            if (volume < 0) {
                volume = 0;
            }
            codec->SetOutputVolume(volume);
            GetDisplay()->ShowNotification("音量 " + std::to_string(volume));
        });

        volume_down_button_.OnLongPress([this]() {
            GetAudioCodec()->SetOutputVolume(0);
            GetDisplay()->ShowNotification("已静音");
        });
    }

    // 物联网初始化，添加对 AI 可见设备
    void InitializeIot() {
        auto& thing_manager = iot::ThingManager::GetInstance();
        thing_manager.AddThing(iot::CreateThing("Speaker"));
        thing_manager.AddThing(iot::CreateThing("Lamp"));
    }

    static void WebSocketServerTask(void* arg) {
        auto* board = static_cast<CompactWifiBoard*>(arg);
        
        // 等待一小段时间确保系统初始化完成
        vTaskDelay(pdMS_TO_TICKS(1000));
        
        auto& server = LocalWebsocketServer::GetInstance();
        
        // 配置读取回调
        server.OnGetConfig([board]() {
            cJSON* root = cJSON_CreateObject();
            if (!root) return std::string("{\"error\":\"Failed to create JSON object\"}");
            
            // WiFi 配置
            Settings wifi_settings("wifi");
            cJSON_AddStringToObject(root, "ssid", wifi_settings.GetString("ssid", "").c_str());
            cJSON_AddStringToObject(root, "hostname", wifi_settings.GetString("hostname", "xiaozhi").c_str());
            cJSON_AddBoolToObject(root, "wifi_connected", WifiStation::GetInstance().IsConnected());
            
            // 设备信息
            cJSON_AddStringToObject(root, "mac_address", SystemInfo::GetMacAddress().c_str());
            cJSON_AddStringToObject(root, "chip_model", SystemInfo::GetChipModelName().c_str());
            cJSON_AddNumberToObject(root, "free_heap", SystemInfo::GetFreeHeapSize());
            
            char* json_str = cJSON_PrintUnformatted(root);
            std::string result = json_str;
            free(json_str);
            cJSON_Delete(root);
            return result;
        });

        // 配置设置回调
        server.OnSetConfig([](const std::string& config_str) {
            cJSON* root = cJSON_Parse(config_str.c_str());
            if (!root) return false;

            bool success = true;
            Settings wifi_settings("wifi");
            cJSON* ssid = cJSON_GetObjectItem(root, "ssid");
            cJSON* password = cJSON_GetObjectItem(root, "password");
            cJSON* hostname = cJSON_GetObjectItem(root, "hostname");

            if (ssid && ssid->valuestring) {
                wifi_settings.SetString("ssid", ssid->valuestring);
                success = true;
            }
            if (password && password->valuestring) {
                wifi_settings.SetString("password", password->valuestring);
                success = true;
            }
            if (hostname && hostname->valuestring) {
                wifi_settings.SetString("hostname", hostname->valuestring);
                success = true;
            }

            cJSON_Delete(root);
            return success;
        });

        // 重启回调
        server.OnReboot([]() {
            esp_restart();
        });

        // 启动服务器
        if (!server.Start(3000)) {
            ESP_LOGE(TAG, "Failed to start WebSocket server");
        } else {
            ESP_LOGI(TAG, "WebSocket server started on port 3000");
        }

        // 任务完成后进入无限循环
        while (true) {
            vTaskDelay(portMAX_DELAY);
        }
    }

public:
    CompactWifiBoard() :
        boot_button_(BOOT_BUTTON_GPIO),
        touch_button_(TOUCH_BUTTON_GPIO),
        volume_up_button_(VOLUME_UP_BUTTON_GPIO),
        volume_down_button_(VOLUME_DOWN_BUTTON_GPIO) {
        InitializeDisplayI2c();
        InitializeButtons();
        InitializeIot();
        
        // 在网络栈初始化后启动 WebSocket 服务器
        xTaskCreate(WebSocketServerTask, "ws_init", 4096, this, 5, nullptr);
    }

    virtual Led* GetLed() override {
        static SingleLed led(BUILTIN_LED_GPIO);
        return &led;
    }

    virtual AudioCodec* GetAudioCodec() override {
#ifdef AUDIO_I2S_METHOD_SIMPLEX
        static NoAudioCodecSimplex audio_codec(AUDIO_INPUT_SAMPLE_RATE, AUDIO_OUTPUT_SAMPLE_RATE,
            AUDIO_I2S_SPK_GPIO_BCLK, AUDIO_I2S_SPK_GPIO_LRCK, AUDIO_I2S_SPK_GPIO_DOUT, AUDIO_I2S_MIC_GPIO_SCK, AUDIO_I2S_MIC_GPIO_WS, AUDIO_I2S_MIC_GPIO_DIN);
#else
        static NoAudioCodecDuplex audio_codec(AUDIO_INPUT_SAMPLE_RATE, AUDIO_OUTPUT_SAMPLE_RATE,
            AUDIO_I2S_GPIO_BCLK, AUDIO_I2S_GPIO_WS, AUDIO_I2S_GPIO_DOUT, AUDIO_I2S_GPIO_DIN);
#endif
        return &audio_codec;
    }

    virtual Display* GetDisplay() override {
        static Ssd1306Display display(display_i2c_bus_, DISPLAY_WIDTH, DISPLAY_HEIGHT, DISPLAY_MIRROR_X, DISPLAY_MIRROR_Y,
                                    &font_puhui_14_1, &font_awesome_14_1);
        return &display;
    }
};

DECLARE_BOARD(CompactWifiBoard);
