#include "globals/global_strings.hpp"
#include "cmd_parser.hpp"
#include "logger.hpp"
#include "configuration/config_parser.hpp"
#include "configuration/read_config.hpp"
#include "system_setup.hpp"
#include "probes_objects/create_probe_objects.hpp"
#include "globals/global_objects.hpp"
#include "posix_signal_handler.hpp"
#include "rules_managment/rules_organizer.hpp"
#include "configuration/schema.inc"
#include "shell_detection/shells_finder.hpp"
#include "globals/global_numbers.hpp"

#include <unistd.h>
#include <filesystem>
#include <iostream>

void safeSetup(int argc, char *argv[]);
void setup(int argc, char *argv[]);
void cleanup();
void setupShellDetection();
int libbpfLogCallback(enum libbpf_print_level level, const char *format, va_list args);

int main(int argc, char *argv[])
{
    if(getuid() != 0)
    {
        std::cerr << "Error: This program must be run as root" << std::endl;
        exit(1);
    }

    owlsm::PosixSignalHandler signal_handler;
    safeSetup(argc, argv);
    signal_handler.waitForExitSignal();
    cleanup();
    return 0;
}

void safeSetup(int argc, char *argv[])
{
    try 
    {
        setup(argc, argv);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Setup failed: '" << e.what() << "' Exiting..." << std::endl;
        exit(1);
    }
    catch (...)
    {
        std::cerr << "Setup failed: Unknown exception. Exiting..." << std::endl;
        exit(1);
    }
}

void setup(int argc, char *argv[])
{
    owlsm::Logger::initialize(owlsm::globals::CURRENT_PROCESS_DIR + "/" + owlsm::globals::LOG_FILE_NAME, LOG_LEVEL_DEBUG);
    LOG_INFO("Starting OWLSM. Version: " + std::string(OWLSM_VERSION_STR));

    owlsm::CmdParser cmd_parser(argc, argv);
    const std::string schema_str(reinterpret_cast<const char*>(g_schema_json), g_schema_json_len);

    std::string config_str;
    if (cmd_parser.isStdin())
    {
        config_str = owlsm::config::readConfigFromStdin();
    }
    else if (!cmd_parser.getConfigPath().empty())
    {
        config_str = owlsm::config::readConfigFromFile(cmd_parser.getConfigPath());
    }

    if (!config_str.empty())
    {
        owlsm::config::ConfigParser config_parser(config_str, schema_str);
        owlsm::globals::g_config = config_parser.getConfig();
        config_parser.ClearRules();
        explicit_bzero(config_str.data(), config_str.size());
        config_str.clear();
    }
    owlsm::Logger::applyConfiguredLogLocation(owlsm::globals::g_config.userspace.log_location);
    owlsm::Logger::getInstance().setLogLevel(owlsm::globals::g_config.userspace.log_level);
    libbpf_set_print(libbpfLogCallback);

    owlsm::RulesOrganizer::add_end_rules(owlsm::globals::g_config.rules_config.rules);
    auto organized_rules = owlsm::RulesOrganizer::organize_rules(owlsm::globals::g_config.rules_config.rules);

    owlsm::SystemSetup::start();
    setupShellDetection();
    owlsm::globals::g_probe_manager = owlsm::CreateProbeObjects::createProbeManager();
    owlsm::globals::g_probe_manager.bpfOpen(organized_rules);
    auto excluded_pids = cmd_parser.getPids();
    excluded_pids.push_back(getpid());
    owlsm::globals::g_probe_manager.bpfLoad(excluded_pids);
    owlsm::globals::g_probe_manager.bpfAttach();

}

void setupShellDetection()
{
    if (!owlsm::globals::g_config.features.shell_commands_monitoring.enabled)
    {
        return;
    }

    const auto shells = owlsm::ShellsFinder::getUniqueShellsFromEtcShells();
    if (shells.empty())
    {
        LOG_WARN("No shells found on the system");
        return;
    }

    owlsm::globals::g_shells_db.init(owlsm::globals::DB_PATH);

    for (const auto& shell : shells)
    {
        owlsm::globals::g_shells_db.set(shell);
        LOG_INFO("Added shell to database: " << shell.path);
    }

    LOG_INFO("Shell detection initialized with " << shells.size() << " shells");
}

void cleanup()
{
    owlsm::globals::g_probe_manager.bpfDetach();
    owlsm::globals::g_probe_manager.bpfDestroy();
    owlsm::Logger::shutdown();
}

int libbpfLogCallback(enum libbpf_print_level level, const char *format, va_list args)
{
    char buffer[owlsm::globals::LIBBPF_LOG_MESSAGE_SIZE] = {};
    std::vsnprintf(buffer, sizeof(buffer), format, args);

    switch (level)
    {
    case LIBBPF_WARN:
        LOG_WARN("libbpf: '" << buffer << "'");
        break;
    case LIBBPF_INFO:
        LOG_INFO("libbpf: '" << buffer << "'");
        break;
    case LIBBPF_DEBUG:
        LOG_DEBUG("libbpf: '" << buffer << "'");
        break;
    default:
        LOG_INFO("libbpf: '" << buffer << "'");
        break;
    }

    return 0;
}

