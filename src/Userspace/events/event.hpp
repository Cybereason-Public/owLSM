#pragma once

#include "events_structs.h"
#include "configuration/rule.hpp"

#include <variant>
#include <cstring>

namespace owlsm::events
{

struct Path
{
    std::string value;

    Path() = default;
    explicit Path(const path_t& p) : value(p.value, p.length) {}
};

struct CommandLine
{
    std::string value;

    CommandLine() = default;
    explicit CommandLine(const command_line_t& c) : value(c.value, c.length) {}
};

struct Filename
{
    std::string value;

    Filename() = default;
    explicit Filename(const filename_t& f) : value(f.value, f.length) {}
};

struct Owner
{
    unsigned int uid = 0;
    unsigned int gid = 0;

    Owner() = default;
    explicit Owner(const owner_t& o) : uid(o.uid), gid(o.gid) {}
};

struct StdioFileDescriptorsAtProcessCreation
{
    file_type stdin_fd = UNKNOWN_FILE_TYPE;
    file_type stdout_fd = UNKNOWN_FILE_TYPE;
    file_type stderr_fd = UNKNOWN_FILE_TYPE;

    StdioFileDescriptorsAtProcessCreation() = default;
    explicit StdioFileDescriptorsAtProcessCreation(const stdio_file_descriptors_at_process_creation_t& s)
        : stdin_fd(s.stdin), stdout_fd(s.stdout), stderr_fd(s.stderr) {}
};

struct File
{
    unsigned long inode = 0;
    unsigned int dev = 0;
    unsigned long long unique_inode_id = 0;
    Path path;
    Owner owner;
    unsigned short mode = 0;
    file_type type = UNKNOWN_FILE_TYPE;
    unsigned char suid = 0;
    unsigned char sgid = 0;
    unsigned long long last_modified_seconds = 0;
    unsigned int nlink = 0;
    Filename filename;

    File() = default;
    explicit File(const file_t& f)
        : inode(f.inode), dev(f.dev), unique_inode_id(f.unique_inode_id), path(f.path), owner(f.owner)
        , mode(f.mode) , type(f.type) , suid(f.suid) , sgid(f.sgid) , last_modified_seconds(f.last_modified_seconds)
        , nlink(f.nlink) , filename(f.filename) {}
};

struct Process
{
    unsigned int pid = 0;
    unsigned int ppid = 0;
    unsigned long long unique_process_id = 0;
    unsigned long long unique_ppid_id = 0;
    unsigned int ruid = 0;
    unsigned int rgid = 0;
    unsigned int euid = 0;
    unsigned int egid = 0;
    unsigned int suid = 0;
    unsigned long long cgroup_id = 0;
    unsigned long long start_time = 0;
    unsigned int ptrace_flags = 0;
    File file;
    CommandLine cmd;
    StdioFileDescriptorsAtProcessCreation stdio_file_descriptors_at_process_creation;
    CommandLine shell_command;

    Process() = default;
    explicit Process(const process_t& p)
        : pid(p.pid) , ppid(p.ppid) , unique_process_id(p.unique_process_id) , unique_ppid_id(p.unique_ppid_id)
        , ruid(p.ruid) , rgid(p.rgid) , euid(p.euid) , egid(p.egid) , suid(p.suid) , cgroup_id(p.cgroup_id)
        , start_time(p.start_time) , ptrace_flags(p.ptrace_flags) , file(p.file) , cmd(p.cmd)
        , stdio_file_descriptors_at_process_creation(p.stdio_file_descriptors_at_process_creation) , shell_command(p.shell_command) {}
};

struct ChownEventData
{
    File file;
    unsigned int requested_owner_uid = 0;
    unsigned int requested_owner_gid = 0;

    ChownEventData() = default;
    explicit ChownEventData(const chown_event_t& e)
        : file(e.file) , requested_owner_uid(e.requested_owner_uid) , requested_owner_gid(e.requested_owner_gid) {}
};

struct ChmodEventData
{
    File file;
    unsigned short requested_mode = 0;

    ChmodEventData() = default;
    explicit ChmodEventData(const chmod_event_t& e)
        : file(e.file) , requested_mode(e.requested_mode) {}
};

struct ForkEventData
{
    ForkEventData() = default;
    explicit ForkEventData(const fork_event_t&) {}
};

struct ExecEventData
{
    Process new_process;

    ExecEventData() = default;
    explicit ExecEventData(const exec_event_t& e)
        : new_process(e.new_process) {}
};

struct ExitEventData
{
    unsigned int exit_code = 0;
    unsigned int signal = 0;

    ExitEventData() = default;
    explicit ExitEventData(const exit_event_t& e)
        : exit_code(e.exit_code) , signal(e.signal) {}
};

struct GenericFileEventData
{
    File file;

    GenericFileEventData() = default;
    explicit GenericFileEventData(const file_create_event_t& e) : file(e.file) {}
    explicit GenericFileEventData(const write_event_t& e) : file(e.file) {}
};

struct RenameEventData
{
    unsigned int flags = 0;
    File source_file;
    File destination_file;

    RenameEventData() = default;
    explicit RenameEventData(const rename_event_t& e)
        : flags(e.flags), source_file(e.source_file), destination_file(e.destination_file) {}
};

struct Ipv4Addresses
{
    unsigned int source_ip = 0;
    unsigned int destination_ip = 0;
};

struct Ipv6Addresses
{
    unsigned int source_ip[4] = {0};
    unsigned int destination_ip[4] = {0};
};

struct SignalEventData
{
    Process process;
    unsigned int signal = 0;

    SignalEventData() = default;
    explicit SignalEventData(const signal_event_t& e)
        : process(e.process), signal(e.signal) {}
};

struct NetworkEventData
{
    connection_direction direction = INCOMING;
    unsigned char protocol = 0;
    unsigned char ip_type = 0;
    unsigned short source_port = 0;
    unsigned short destination_port = 0;
    std::variant<Ipv4Addresses, Ipv6Addresses> addresses;

    NetworkEventData() : addresses(Ipv4Addresses{}) {}
    explicit NetworkEventData(const network_event_t& e)
        : direction(e.direction), protocol(e.protocol), ip_type(e.ip_type), source_port(e.source_port)
        , destination_port(e.destination_port)
    {
        if (ip_type == AF_INET)
        {
            Ipv4Addresses ipv4;
            ipv4.source_ip = e.addresses.ipv4.source_ip;
            ipv4.destination_ip = e.addresses.ipv4.destination_ip;
            addresses = ipv4;
        }
        else
        {
            Ipv6Addresses ipv6;
            std::memcpy(ipv6.source_ip, e.addresses.ipv6.source_ip, sizeof(ipv6.source_ip));
            std::memcpy(ipv6.destination_ip, e.addresses.ipv6.destination_ip, sizeof(ipv6.destination_ip));
            addresses = ipv6;
        }
    }
};

using EventData = std::variant<
    ChownEventData,
    ChmodEventData,
    ForkEventData,
    ExecEventData,
    ExitEventData,
    GenericFileEventData,
    RenameEventData,
    NetworkEventData,
    SignalEventData
>;

struct Event
{
    using RawType = event_t;

    unsigned long long id = 0;
    event_type type = EXEC;
    rule_action action = ALLOW_EVENT;
    unsigned char had_error_while_handling = 0;
    unsigned long long time = 0;
    Process process;
    Process parent_process;
    EventData data;

    unsigned int matched_rule_id = 0;
    config::RuleMetadata matched_rule_metadata;
    bool is_enriched = false;

    Event() = default;

    explicit Event(const RawType& ev)
        : id(ev.id), type(ev.type), action(ev.action), had_error_while_handling(ev.had_error_while_handling)
        , time(ev.time), process(ev.process), parent_process(ev.parent_process), matched_rule_id(ev.matched_rule_id)
    {
        switch (ev.type)
        {
        case CHOWN: data = ChownEventData(ev.data.chown); break;
        case CHMOD: data = ChmodEventData(ev.data.chmod); break;
        case FORK:  data = ForkEventData(ev.data.fork); break;
        case EXEC:  data = ExecEventData(ev.data.exec); break;
        case EXIT:  data = ExitEventData(ev.data.exit); break;
        case FILE_CREATE: data = GenericFileEventData(ev.data.file_create); break;
        case WRITE: data = GenericFileEventData(ev.data.write); break;
        case READ:  data = GenericFileEventData(ev.data.read); break;
        case UNLINK: data = GenericFileEventData(ev.data.unlink); break;
        case RENAME: data = RenameEventData(ev.data.rename); break;
        case NETWORK: data = NetworkEventData(ev.data.network); break;
        case MKDIR: data = GenericFileEventData(ev.data.mkdir); break;
        case RMDIR: data = GenericFileEventData(ev.data.rmdir); break;
        case SIGNAL: data = SignalEventData(ev.data.signal); break;
        }
    }
};

struct Error
{
    using RawType = error_report_t;

    int error_code = 0;
    std::string location;
    std::string details;
    std::string hook_name;

    bool is_enriched = false;

    Error() = default;

    explicit Error(const RawType& e)
        : error_code(e.error_code)
        , location(e.location, strnlen(e.location, ERROR_DETAILS_MAX / 4))
        , details(e.details, strnlen(e.details, ERROR_DETAILS_MAX))
        , hook_name(e.hook_name, strnlen(e.hook_name, HOOK_NAME_MAX_LENGTH))
    {}
};

}

