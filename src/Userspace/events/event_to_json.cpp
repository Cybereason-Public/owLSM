#include "events/event_to_json.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

NLOHMANN_JSON_SERIALIZE_ENUM(file_type, {
    {UNKNOWN_FILE_TYPE, "UNKNOWN_FILE_TYPE"},
    {DIRECTORY, "DIRECTORY"},
    {SYMLINK, "SYMLINK"},
    {BLOCK_DEVICE, "BLOCK_DEVICE"},
    {CHAR_DEVICE, "CHAR_DEVICE"},
    {REGULAR_FILE, "REGULAR_FILE"},
    {SOCKET, "SOCKET"},
    {FIFO, "FIFO"},
    {NO_FILE, "NO_FILE"},
})

namespace owlsm::config
{
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(owlsm::config::RuleMetadata, description)
}

namespace owlsm::events
{

static std::string ipv4_to_string(uint32_t be_addr)
{
    char buf[INET_ADDRSTRLEN] = {0};
    in_addr a{};
    a.s_addr = be_addr;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

static std::string ipv6_to_string(const unsigned int bytes[4])
{
    char buf[INET6_ADDRSTRLEN] = {0};
    in6_addr a6{};
    std::memcpy(a6.s6_addr, bytes, sizeof(a6.s6_addr));
    inet_ntop(AF_INET6, &a6, buf, sizeof(buf));
    return buf;
}

void to_json(nlohmann::json& j, const Path& p) { j = p.value; }
void to_json(nlohmann::json& j, const CommandLine& c) { j = c.value; }
void to_json(nlohmann::json& j, const Filename& f) { j = f.value; }

void to_json(nlohmann::json& j, const StdioFileDescriptorsAtProcessCreation& s)
{
    j = nlohmann::json{{"stdin", s.stdin_fd}, {"stdout", s.stdout_fd}, {"stderr", s.stderr_fd}};
}

NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Owner, uid, gid)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(File, inode, dev, path, owner, mode, type, suid, sgid, last_modified_seconds, nlink, filename)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(Process, pid, ppid, ruid, rgid, euid, egid, suid, cgroup_id, start_time, ptrace_flags, file, cmd, stdio_file_descriptors_at_process_creation, shell_command)
NLOHMANN_DEFINE_TYPE_NON_INTRUSIVE(ExitEventData, exit_code, signal)

void to_json(nlohmann::json& j, const GenericFileEventData& e)
{
    j = nlohmann::json{{"target", {{"file", e.file}}}};
}

void to_json(nlohmann::json& j, const ChownEventData& e)
{
    j = nlohmann::json{
        {"target", {{"file", e.file}}},
        {"chown", {
            {"requested_owner_uid", e.requested_owner_uid},
            {"requested_owner_gid", e.requested_owner_gid}
        }}
    };
}

void to_json(nlohmann::json& j, const ChmodEventData& e)
{
    j = nlohmann::json{
        {"target", {{"file", e.file}}},
        {"chmod", {{"requested_mode", e.requested_mode}}}
    };
}

void to_json(nlohmann::json& j, const ExecEventData& e)
{
    j = nlohmann::json{{"target", {{"process", e.new_process}}}};
}

void to_json(nlohmann::json& j, const RenameEventData& e)
{
    j = nlohmann::json{
        {"flags", e.flags},
        {"rename", {
            {"source_file", e.source_file},
            {"destination_file", e.destination_file}
        }}
    };
}

void to_json(nlohmann::json& j, const ForkEventData&)
{
    j = nlohmann::json::object();
}

void to_json(nlohmann::json& j, const NetworkEventData& e)
{
    std::string source_ip;
    std::string destination_ip;

    if (e.ip_type == AF_INET)
    {
        const auto& ipv4 = std::get<Ipv4Addresses>(e.addresses);
        source_ip = ipv4_to_string(ipv4.source_ip);
        destination_ip = ipv4_to_string(ipv4.destination_ip);
    }
    else
    {
        const auto& ipv6 = std::get<Ipv6Addresses>(e.addresses);
        source_ip = ipv6_to_string(ipv6.source_ip);
        destination_ip = ipv6_to_string(ipv6.destination_ip);
    }

    j = nlohmann::json{
        {"network", {
            {"direction", ::to_string(e.direction)},
            {"source_ip", source_ip},
            {"destination_ip", destination_ip},
            {"source_port", e.source_port},
            {"destination_port", e.destination_port},
            {"protocol", e.protocol},
            {"ip_type", e.ip_type}
        }}
    };
}

template <>
void EventToJson<Event>::write_root_event_json(nlohmann::json& j, const Event& ev)
{
    j = nlohmann::json{
        {"id", ev.id},
        {"type", ::to_string(ev.type)},
        {"action", ::to_string(ev.action)},
        {"matched_rule_id", ev.matched_rule_id},
        {"matched_rule_metadata", ev.matched_rule_metadata},
        {"had_error", ev.had_error_while_handling},
        {"process", ev.process},
        {"parent_process", ev.parent_process},
        {"time", ev.time}
    };

    std::visit([&j](const auto& data) {
        to_json(j["data"], data);
    }, ev.data);
}

template <>
void EventToJson<Error>::write_root_error_json(nlohmann::json& j, const Error& e)
{
    j = nlohmann::json{
        {"error_code", e.error_code},
        {"location", e.location},
        {"details", e.details}
    };
}

} // namespace owlsm::events
