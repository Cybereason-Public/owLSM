#pragma once

#include <string>
#include <vector>

namespace owlsm {

class CmdParser {
public:
    CmdParser(int argc, char** argv);

    const std::string& getConfigPath() const { return m_config_path; }
    bool isStdin() const { return m_use_stdin; }
    const std::vector<unsigned int>& getPids() const { return m_pids; }

    CmdParser(const CmdParser&) = delete;
    CmdParser& operator=(const CmdParser&) = delete;
    CmdParser(CmdParser&&) = delete;
    CmdParser& operator=(CmdParser&&) = delete;

private:
    std::string m_config_path;
    bool m_use_stdin = false;
    std::vector<unsigned int> m_pids;
};

}

