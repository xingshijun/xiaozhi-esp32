#ifndef SETTINGS_H
#define SETTINGS_H

#include <string>
#include <nvs_flash.h>
#include <vector>

class Settings {
public:
    Settings(const std::string& ns, bool read_write = false);
    ~Settings();

    std::string GetString(const std::string& key, const std::string& default_value = "");
    void SetString(const std::string& key, const std::string& value);
    int32_t GetInt(const std::string& key, int32_t default_value = 0);
    void SetInt(const std::string& key, int32_t value);
    bool GetBool(const std::string& key, bool default_value = false);
    void SetBool(const std::string& key, bool value);
    void EraseKey(const std::string& key);
    void EraseAll();
    
    // 新增方法
    std::vector<std::string> GetAllKeys();
    bool Contains(const std::string& key);
    bool IsString(const std::string& key);
    bool IsInt(const std::string& key);
    bool IsBool(const std::string& key);

private:
    std::string ns_;
    nvs_handle_t nvs_handle_ = 0;
    bool read_write_ = false;
    bool dirty_ = false;

    // 添加 ValueType 枚举定义
    enum class ValueType {
        String,
        Int,
        Bool,
        Unknown
    };
    
    // 添加 GetValueType 方法声明
    ValueType GetValueType(const std::string& key);
};

#endif
