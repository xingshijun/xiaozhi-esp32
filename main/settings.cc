#include "settings.h"

#include <esp_log.h>
#include <nvs_flash.h>

#define TAG "Settings"

Settings::Settings(const std::string& ns, bool read_write) : ns_(ns), read_write_(read_write) {
    nvs_open(ns.c_str(), read_write_ ? NVS_READWRITE : NVS_READONLY, &nvs_handle_);
}

Settings::~Settings() {
    if (nvs_handle_ != 0) {
        if (read_write_ && dirty_) {
            ESP_ERROR_CHECK(nvs_commit(nvs_handle_));
        }
        nvs_close(nvs_handle_);
    }
}

std::string Settings::GetString(const std::string& key, const std::string& default_value) {
    if (nvs_handle_ == 0) {
        return default_value;
    }

    size_t length = 0;
    if (nvs_get_str(nvs_handle_, key.c_str(), nullptr, &length) != ESP_OK) {
        return default_value;
    }

    std::string value;
    value.resize(length);
    ESP_ERROR_CHECK(nvs_get_str(nvs_handle_, key.c_str(), value.data(), &length));
    while (!value.empty() && value.back() == '\0') {
        value.pop_back();
    }
    return value;
}

void Settings::SetString(const std::string& key, const std::string& value) {
    if (read_write_) {
        ESP_ERROR_CHECK(nvs_set_str(nvs_handle_, key.c_str(), value.c_str()));
        dirty_ = true;
    } else {
        ESP_LOGW(TAG, "Namespace %s is not open for writing", ns_.c_str());
    }
}

int32_t Settings::GetInt(const std::string& key, int32_t default_value) {
    if (nvs_handle_ == 0) {
        return default_value;
    }

    int32_t value;
    if (nvs_get_i32(nvs_handle_, key.c_str(), &value) != ESP_OK) {
        return default_value;
    }
    return value;
}

void Settings::SetInt(const std::string& key, int32_t value) {
    if (read_write_) {
        ESP_ERROR_CHECK(nvs_set_i32(nvs_handle_, key.c_str(), value));
        dirty_ = true;
    } else {
        ESP_LOGW(TAG, "Namespace %s is not open for writing", ns_.c_str());
    }
}

bool Settings::GetBool(const std::string& key, bool default_value) {
    if (nvs_handle_ == 0) {
        return default_value;
    }

    uint8_t value;
    if (nvs_get_u8(nvs_handle_, key.c_str(), &value) != ESP_OK) {
        return default_value;
    }
    return value != 0;
}

void Settings::SetBool(const std::string& key, bool value) {
    if (read_write_) {
        ESP_ERROR_CHECK(nvs_set_u8(nvs_handle_, key.c_str(), value ? 1 : 0));
        dirty_ = true;
    } else {
        ESP_LOGW(TAG, "Namespace %s is not open for writing", ns_.c_str());
    }
}

void Settings::EraseKey(const std::string& key) {
    if (read_write_) {
        auto ret = nvs_erase_key(nvs_handle_, key.c_str());
        if (ret != ESP_ERR_NVS_NOT_FOUND) {
            ESP_ERROR_CHECK(ret);
        }
    } else {
        ESP_LOGW(TAG, "Namespace %s is not open for writing", ns_.c_str());
    }
}

void Settings::EraseAll() {
    if (read_write_) {
        ESP_ERROR_CHECK(nvs_erase_all(nvs_handle_));
    } else {
        ESP_LOGW(TAG, "Namespace %s is not open for writing", ns_.c_str());
    }
}

std::vector<std::string> Settings::GetAllKeys() {
    std::vector<std::string> keys;
    if (nvs_handle_ == 0) {
        return keys;
    }

    nvs_iterator_t it = nullptr;
    esp_err_t res = nvs_entry_find(ns_.c_str(), NULL, NVS_TYPE_ANY, &it);
    while (res == ESP_OK) {
        nvs_entry_info_t info;
        nvs_entry_info(it, &info);
        keys.push_back(info.key);
        res = nvs_entry_next(&it);
    }
    nvs_release_iterator(it);
    
    return keys;
}

Settings::ValueType Settings::GetValueType(const std::string& key) {
    if (nvs_handle_ == 0) {
        return ValueType::Unknown;
    }
    
    size_t required_size;
    
    // 尝试获取字符串长度
    if (nvs_get_str(nvs_handle_, key.c_str(), nullptr, &required_size) == ESP_OK) {
        return ValueType::String;
    }
    
    // 尝试获取整数
    int32_t value;
    if (nvs_get_i32(nvs_handle_, key.c_str(), &value) == ESP_OK) {
        return ValueType::Int;
    }
    
    // 尝试获取布尔值
    uint8_t bool_value;
    if (nvs_get_u8(nvs_handle_, key.c_str(), &bool_value) == ESP_OK) {
        return ValueType::Bool;
    }
    
    return ValueType::Unknown;
}

bool Settings::Contains(const std::string& key) {
    return GetValueType(key) != ValueType::Unknown;
}

bool Settings::IsString(const std::string& key) {
    return GetValueType(key) == ValueType::String;
}

bool Settings::IsInt(const std::string& key) {
    return GetValueType(key) == ValueType::Int;
}

bool Settings::IsBool(const std::string& key) {
    return GetValueType(key) == ValueType::Bool;
}
