#pragma once

#include <string>
#include <fstream>
#include <sstream>
#include <iostream>
#include <stdexcept>
#include <future>
#include <chrono>

namespace owlsm::config
{

constexpr int STDIN_TIMEOUT_SECONDS = 10;

inline std::string readConfigFromFile(const std::string& filepath)
{
    std::ifstream in(filepath);
    if (!in)
    {
        throw std::runtime_error("Failed to open config file: " + filepath);
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

inline std::string readConfigFromStdin()
{
    auto future = std::async(std::launch::async, []()
    {
        std::ostringstream ss;
        ss << std::cin.rdbuf();
        return ss.str();
    });

    if (future.wait_for(std::chrono::seconds(STDIN_TIMEOUT_SECONDS)) == std::future_status::timeout)
    {
        throw std::runtime_error("Timed out waiting for config on stdin after " +
                                 std::to_string(STDIN_TIMEOUT_SECONDS) + " seconds");
    }

    auto result = future.get();
    if (result.empty())
    {
        throw std::runtime_error("No data received on stdin");
    }
    return result;
}

}
