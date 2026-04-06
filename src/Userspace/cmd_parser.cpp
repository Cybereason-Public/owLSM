#include "cmd_parser.hpp"

#include <cxxopts/cxxopts.hpp>
#include <iostream>
#include <cstdlib>

namespace owlsm {

CmdParser::CmdParser(int argc, char** argv) 
{
    try 
    {
        cxxopts::Options options(argv[0], "OWLSM - eBPF Security Monitoring");
        
        options.add_options()
            ("c,config", "Path to configuration file (cannot use with --stdin)", cxxopts::value<std::string>())
            ("stdin", "Read configuration from stdin (cannot use with -c)")
            ("e,exclude-pid", "PID to exclude from monitoring (can be specified multiple times)", cxxopts::value<std::vector<unsigned int>>())
            ("h,help", "Show help message");

        auto result = options.parse(argc, argv);

        if (result.count("help")) 
        {
            std::cout << options.help() << std::endl;
            std::cout << "Example: " << argv[0] << " -c /path/to/config.json -e 123 -e 456" << std::endl;
            std::exit(0);
        }

        const auto config_count = result.count("config");
        const auto stdin_count = result.count("stdin");

        if (config_count > 0 && stdin_count > 0)
        {
            std::cerr << "Error: --stdin and -c/--config cannot be used together.\n";
            std::cerr << "Use -h for help.\n";
            std::exit(1);
        }

        if (config_count > 1) 
        {
            std::cerr << "Error: -c/--config <path> is required at most once.\n";
            std::cerr << "Use -h for help.\n";
            std::exit(1);
        }
        else if (config_count == 1)
        {
            m_config_path = result["config"].as<std::string>();
        }

        m_use_stdin = (stdin_count > 0);

        if (result.count("exclude-pid")) 
        {
            m_pids = result["exclude-pid"].as<std::vector<unsigned int>>();
        }

    } 
    catch (const cxxopts::exceptions::exception& e) 
    {
        std::cerr << "Command-line parsing error: " << e.what() << "\n";
        std::cerr << "Use -h for help.\n";
        std::exit(1);
    }
}

}
