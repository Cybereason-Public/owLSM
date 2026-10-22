#include <gtest/gtest.h>

#include "events/event_to_json.hpp"

#include <3rd_party/nlohmann/json.hpp>

#include <arpa/inet.h>

#include <cstddef>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

class EventToJsonTest : public ::testing::Test
{
public:
    static constexpr unsigned long long EVENT_ID = 7;
    static constexpr unsigned long long EVENT_TIME = 1700000000;
    static constexpr unsigned int MATCHED_RULE_ID = 42;
    static constexpr unsigned char HAD_ERROR = 0;
    static constexpr bool EVENT_IS_ENRICHED = true;

    static constexpr unsigned int ACTOR_PID = 100;
    static constexpr unsigned int ACTOR_NS_PID = 10;
    static constexpr unsigned int ACTOR_PPID = 50;
    static constexpr unsigned int ACTOR_NS_PPID = 5;
    static constexpr unsigned long long ACTOR_UNIQUE_PROCESS_ID = 1001;
    static constexpr unsigned long long ACTOR_UNIQUE_PPID_ID = 1002;
    static constexpr unsigned int ACTOR_RUID = 1000;
    static constexpr unsigned int ACTOR_RGID = 1001;
    static constexpr unsigned int ACTOR_EUID = 0;
    static constexpr unsigned int ACTOR_EGID = 10;
    static constexpr unsigned int ACTOR_SUID = 0;
    static constexpr unsigned long long ACTOR_CGROUP_ID = 77;
    static constexpr unsigned long long ACTOR_CONTAINER_ID = 0xabc;
    static constexpr unsigned long long ACTOR_START_TIME = 111;
    static constexpr unsigned int ACTOR_PTRACE_FLAGS = 2;
    static constexpr unsigned long ACTOR_INODE = 11;
    static constexpr unsigned int ACTOR_DEV = 8;
    static constexpr unsigned long long ACTOR_UNIQUE_INODE_ID = 777;
    static constexpr const char* ACTOR_PATH = "/usr/bin/app";
    static constexpr unsigned int ACTOR_UID = 0;
    static constexpr unsigned int ACTOR_GID = 0;
    static constexpr unsigned short ACTOR_MODE = 493;
    static constexpr file_type ACTOR_FILE_TYPE = REGULAR_FILE;
    static constexpr unsigned char ACTOR_FILE_SUID = 1;
    static constexpr unsigned char ACTOR_FILE_SGID = 0;
    static constexpr unsigned long long ACTOR_LAST_MODIFIED_SECONDS = 222;
    static constexpr unsigned int ACTOR_NLINK = 1;
    static constexpr const char* ACTOR_FILENAME = "app";
    static constexpr const char* ACTOR_CMD = "/usr/bin/app --flag";
    static constexpr file_type ACTOR_STDIN = REGULAR_FILE;
    static constexpr file_type ACTOR_STDOUT = SOCKET;
    static constexpr file_type ACTOR_STDERR = FIFO;
    static constexpr const char* ACTOR_SHELL_COMMAND = "";

    static constexpr unsigned int PARENT_PID = 50;
    static constexpr unsigned int PARENT_NS_PID = 5;
    static constexpr unsigned int PARENT_PPID = 1;
    static constexpr unsigned int PARENT_NS_PPID = 1;
    static constexpr unsigned long long PARENT_UNIQUE_PROCESS_ID = 2001;
    static constexpr unsigned long long PARENT_UNIQUE_PPID_ID = 2002;
    static constexpr unsigned int PARENT_RUID = 0;
    static constexpr unsigned int PARENT_RGID = 0;
    static constexpr unsigned int PARENT_EUID = 0;
    static constexpr unsigned int PARENT_EGID = 0;
    static constexpr unsigned int PARENT_SUID = 0;
    static constexpr unsigned long long PARENT_CGROUP_ID = 1;
    static constexpr unsigned long long PARENT_CONTAINER_ID = 0;
    static constexpr unsigned long long PARENT_START_TIME = 10;
    static constexpr unsigned int PARENT_PTRACE_FLAGS = 0;
    static constexpr unsigned long PARENT_INODE = 3;
    static constexpr unsigned int PARENT_DEV = 8;
    static constexpr unsigned long long PARENT_UNIQUE_INODE_ID = 3;
    static constexpr const char* PARENT_PATH = "/bin/bash";
    static constexpr unsigned int PARENT_UID = 0;
    static constexpr unsigned int PARENT_GID = 0;
    static constexpr unsigned short PARENT_MODE = 493;
    static constexpr file_type PARENT_FILE_TYPE = REGULAR_FILE;
    static constexpr unsigned char PARENT_FILE_SUID = 0;
    static constexpr unsigned char PARENT_FILE_SGID = 0;
    static constexpr unsigned long long PARENT_LAST_MODIFIED_SECONDS = 10;
    static constexpr unsigned int PARENT_NLINK = 1;
    static constexpr const char* PARENT_FILENAME = "bash";
    static constexpr const char* PARENT_CMD = "/bin/bash";
    static constexpr file_type PARENT_STDIN = UNKNOWN_FILE_TYPE;
    static constexpr file_type PARENT_STDOUT = UNKNOWN_FILE_TYPE;
    static constexpr file_type PARENT_STDERR = UNKNOWN_FILE_TYPE;
    static constexpr const char* PARENT_SHELL_COMMAND = "";

    static constexpr unsigned long CHMOD_INODE = 20;
    static constexpr unsigned int CHMOD_DEV = 8;
    static constexpr unsigned long long CHMOD_UNIQUE_INODE_ID = 55;
    static constexpr const char* CHMOD_PATH = "/tmp/x";
    static constexpr unsigned int CHMOD_UID = 1000;
    static constexpr unsigned int CHMOD_GID = 1000;
    static constexpr unsigned short CHMOD_MODE = 420;
    static constexpr file_type CHMOD_FILE_TYPE = REGULAR_FILE;
    static constexpr unsigned char CHMOD_FILE_SUID = 0;
    static constexpr unsigned char CHMOD_FILE_SGID = 0;
    static constexpr unsigned long long CHMOD_LAST_MODIFIED_SECONDS = 333;
    static constexpr unsigned int CHMOD_NLINK = 1;
    static constexpr const char* CHMOD_FILENAME = "x";
    static constexpr unsigned short CHMOD_REQUESTED_MODE = 493;

    static constexpr int ERROR_CODE = 13;
    static constexpr const char* ERROR_LOCATION = "load_program";
    static constexpr const char* ERROR_DETAILS = "permission denied";
    static constexpr const char* ERROR_HOOK_NAME = "sys_execve";
    static constexpr bool ERROR_IS_ENRICHED = true;

    static constexpr const char* ESCAPED_PATH = "a\"b\\c";

    static constexpr const char* RULE_TITLE = "Suspicious chmod";
    static constexpr rule_severity MATCHED_RULE_SEVERITY = RULE_SEVERITY_HIGH;
    static constexpr const char* RULE_MITRE_TAG_PERMISSIONS = "T1222";
    static constexpr const char* RULE_MITRE_TAG_LINUX = "T1222.002";

    static constexpr connection_direction NETWORK_DIRECTION = OUTGOING;
    static constexpr const char* NETWORK_SOURCE_IP = "127.0.0.1";
    static constexpr const char* NETWORK_DESTINATION_IP = "10.1.2.3";
    static constexpr unsigned short NETWORK_SOURCE_PORT = 443;
    static constexpr unsigned short NETWORK_DESTINATION_PORT = 54321;
    static constexpr unsigned char NETWORK_PROTOCOL = IPPROTO_TCP;
    static constexpr unsigned char NETWORK_IP_TYPE = AF_INET;

    static constexpr connection_direction NETWORK_V6_DIRECTION = INCOMING;
    static constexpr const char* NETWORK_V6_SOURCE_IP = "::1";
    static constexpr const char* NETWORK_V6_DESTINATION_IP = "2001:db8::1";
    static constexpr unsigned char NETWORK_V6_IP_TYPE = AF_INET6;

    static constexpr unsigned int CHOWN_REQUESTED_UID = 0;
    static constexpr unsigned int CHOWN_REQUESTED_GID = 1000;
    static constexpr unsigned int EXIT_CODE = 137;
    static constexpr unsigned int EXIT_SIGNAL = 9;
    static constexpr unsigned int RENAME_FLAGS = 1;
    static constexpr unsigned int TARGET_SIGNAL = 15;
    static constexpr unsigned int PTRACE_MODE = 16;

    static constexpr unsigned long long SECOND_EVENT_ID = 8;
    static constexpr const char* EMPTY_TEXT = "";
    static constexpr int EMPTY_ERROR_CODE = 0;
    static constexpr const char* INVALID_UTF8_PATH = "\xff";

    static constexpr const char* RULE_DESCRIPTION = "Changed file mode";
    static constexpr const char* RULE_NAME = "chmod_suspicious";
    static constexpr const char* RULE_AUTHOR = "owlsm";
    static constexpr const char* RULE_STATUS = "stable";
    static constexpr rule_severity CRITICAL_RULE_SEVERITY = RULE_SEVERITY_CRITICAL;
    static constexpr rule_severity INVALID_RULE_SEVERITY = static_cast<rule_severity>(6);

    static constexpr const char* K8S_POD_UID = "uid-1";
    static constexpr const char* K8S_POD_NAMESPACE = "default";
    static constexpr const char* K8S_POD_NAME = "nginx";
    static constexpr const char* K8S_LABEL_APP = "app";
    static constexpr const char* K8S_LABEL_APP_VALUE = "nginx";
    static constexpr const char* K8S_LABEL_TIER = "tier";
    static constexpr const char* K8S_LABEL_TIER_VALUE = "frontend";
    static constexpr bool K8S_HOST_EVENT = false;

    static constexpr file_type UNNAMED_FILE_TYPE = static_cast<file_type>(9);
    static constexpr const char* UTF8_PATH = "caf\xc3\xa9";

protected:
    static void expectJsonEqual(const nlohmann::json& actual, const nlohmann::json& expected)
    {
        EXPECT_EQ(actual, expected) << "actual: " << actual.dump() << "\nexpected: " << expected.dump();
    }

    template <typename MessageType>
    static nlohmann::json serialize(const MessageType& message)
    {
        owlsm::events::EventToJson<MessageType> serializer;
        const std::vector<std::shared_ptr<MessageType>> messages{
            std::make_shared<MessageType>(message)
        };
        const std::vector<nlohmann::json> documents = parseDocuments(render(serializer, messages));
        return documents.at(0);
    }

    template <typename MessageType>
    static std::string render(
        owlsm::events::EventToJson<MessageType>& serializer,
        const std::vector<std::shared_ptr<MessageType>>& messages)
    {
        serializer.buildOutputBuffer(messages);
        return bufferText(serializer);
    }

    template <typename MessageType>
    static std::string bufferText(const owlsm::events::EventToJson<MessageType>& serializer)
    {
        const auto* const output_bytes = static_cast<const char*>(serializer.data());
        return std::string(output_bytes, serializer.size());
    }

    static std::vector<nlohmann::json> parseDocuments(const std::string& output)
    {
        std::vector<nlohmann::json> documents;
        std::size_t start = 0;
        while (start < output.size())
        {
            const std::size_t newline = output.find('\n', start);
            const std::size_t count = (newline == std::string::npos) ? (output.size() - start) : (newline - start);
            if (count > 0)
            {
                documents.push_back(nlohmann::json::parse(output.substr(start, count)));
            }
            if (newline == std::string::npos)
            {
                break;
            }
            start = newline + 1;
        }
        return documents;
    }

    static std::shared_ptr<owlsm::events::Event> shareEvent(owlsm::events::Event event)
    {
        return std::make_shared<owlsm::events::Event>(std::move(event));
    }

    static owlsm::events::Event makeBaseEvent()
    {
        owlsm::events::Event event;
        event.id = EVENT_ID;
        event.type = FORK;
        event.action = ALLOW_EVENT;
        event.had_error_while_handling = HAD_ERROR;
        event.time = EVENT_TIME;
        event.matched_rule_id = MATCHED_RULE_ID;
        event.is_enriched = EVENT_IS_ENRICHED;
        event.process = actorProcess();
        event.parent_process = parentProcess();
        event.data = owlsm::events::ForkEventData{};
        return event;
    }

    static owlsm::events::Process actorProcess()
    {
        owlsm::events::Process process;
        process.pid = ACTOR_PID;
        process.ns_pid = ACTOR_NS_PID;
        process.ppid = ACTOR_PPID;
        process.ns_ppid = ACTOR_NS_PPID;
        process.unique_process_id = ACTOR_UNIQUE_PROCESS_ID;
        process.unique_ppid_id = ACTOR_UNIQUE_PPID_ID;
        process.ruid = ACTOR_RUID;
        process.rgid = ACTOR_RGID;
        process.euid = ACTOR_EUID;
        process.egid = ACTOR_EGID;
        process.suid = ACTOR_SUID;
        process.cgroup_id = ACTOR_CGROUP_ID;
        process.container_id = ACTOR_CONTAINER_ID;
        process.start_time = ACTOR_START_TIME;
        process.ptrace_flags = ACTOR_PTRACE_FLAGS;
        process.file.inode = ACTOR_INODE;
        process.file.dev = ACTOR_DEV;
        process.file.unique_inode_id = ACTOR_UNIQUE_INODE_ID;
        process.file.path.value = ACTOR_PATH;
        process.file.owner.uid = ACTOR_UID;
        process.file.owner.gid = ACTOR_GID;
        process.file.mode = ACTOR_MODE;
        process.file.type = ACTOR_FILE_TYPE;
        process.file.suid = ACTOR_FILE_SUID;
        process.file.sgid = ACTOR_FILE_SGID;
        process.file.last_modified_seconds = ACTOR_LAST_MODIFIED_SECONDS;
        process.file.nlink = ACTOR_NLINK;
        process.file.filename.value = ACTOR_FILENAME;
        process.cmd.value = ACTOR_CMD;
        process.stdio_file_descriptors_at_process_creation.stdin_fd = ACTOR_STDIN;
        process.stdio_file_descriptors_at_process_creation.stdout_fd = ACTOR_STDOUT;
        process.stdio_file_descriptors_at_process_creation.stderr_fd = ACTOR_STDERR;
        process.shell_command.value = ACTOR_SHELL_COMMAND;
        return process;
    }

    static owlsm::events::Process parentProcess()
    {
        owlsm::events::Process process;
        process.pid = PARENT_PID;
        process.ns_pid = PARENT_NS_PID;
        process.ppid = PARENT_PPID;
        process.ns_ppid = PARENT_NS_PPID;
        process.unique_process_id = PARENT_UNIQUE_PROCESS_ID;
        process.unique_ppid_id = PARENT_UNIQUE_PPID_ID;
        process.ruid = PARENT_RUID;
        process.rgid = PARENT_RGID;
        process.euid = PARENT_EUID;
        process.egid = PARENT_EGID;
        process.suid = PARENT_SUID;
        process.cgroup_id = PARENT_CGROUP_ID;
        process.container_id = PARENT_CONTAINER_ID;
        process.start_time = PARENT_START_TIME;
        process.ptrace_flags = PARENT_PTRACE_FLAGS;
        process.file.inode = PARENT_INODE;
        process.file.dev = PARENT_DEV;
        process.file.unique_inode_id = PARENT_UNIQUE_INODE_ID;
        process.file.path.value = PARENT_PATH;
        process.file.owner.uid = PARENT_UID;
        process.file.owner.gid = PARENT_GID;
        process.file.mode = PARENT_MODE;
        process.file.type = PARENT_FILE_TYPE;
        process.file.suid = PARENT_FILE_SUID;
        process.file.sgid = PARENT_FILE_SGID;
        process.file.last_modified_seconds = PARENT_LAST_MODIFIED_SECONDS;
        process.file.nlink = PARENT_NLINK;
        process.file.filename.value = PARENT_FILENAME;
        process.cmd.value = PARENT_CMD;
        process.stdio_file_descriptors_at_process_creation.stdin_fd = PARENT_STDIN;
        process.stdio_file_descriptors_at_process_creation.stdout_fd = PARENT_STDOUT;
        process.stdio_file_descriptors_at_process_creation.stderr_fd = PARENT_STDERR;
        process.shell_command.value = PARENT_SHELL_COMMAND;
        return process;
    }

    static owlsm::events::File chmodTargetFile()
    {
        owlsm::events::File file;
        file.inode = CHMOD_INODE;
        file.dev = CHMOD_DEV;
        file.unique_inode_id = CHMOD_UNIQUE_INODE_ID;
        file.path.value = CHMOD_PATH;
        file.owner.uid = CHMOD_UID;
        file.owner.gid = CHMOD_GID;
        file.mode = CHMOD_MODE;
        file.type = CHMOD_FILE_TYPE;
        file.suid = CHMOD_FILE_SUID;
        file.sgid = CHMOD_FILE_SGID;
        file.last_modified_seconds = CHMOD_LAST_MODIFIED_SECONDS;
        file.nlink = CHMOD_NLINK;
        file.filename.value = CHMOD_FILENAME;
        return file;
    }

    static unsigned int ipv4Address(const char* text)
    {
        in_addr address{};
        const int parsed = inet_pton(AF_INET, text, &address);
        EXPECT_EQ(parsed, 1);
        return address.s_addr;
    }

    static void ipv6Address(const char* text, unsigned int out[4])
    {
        in6_addr address{};
        const int parsed = inet_pton(AF_INET6, text, &address);
        EXPECT_EQ(parsed, 1);
        std::memcpy(out, address.s6_addr, sizeof(address.s6_addr));
    }

    static nlohmann::json expectedProcess(const owlsm::events::Process& process)
    {
        return {
            {"pid", process.pid},
            {"ns_pid", process.ns_pid},
            {"ppid", process.ppid},
            {"ns_ppid", process.ns_ppid},
            {"ruid", process.ruid},
            {"rgid", process.rgid},
            {"euid", process.euid},
            {"egid", process.egid},
            {"suid", process.suid},
            {"cgroup_id", process.cgroup_id},
            {"start_time", process.start_time},
            {"ptrace_flags", process.ptrace_flags},
            {"file", expectedFile(process.file)},
            {"cmd", process.cmd.value},
            {"stdio_file_descriptors_at_process_creation", {
                {"stdin", fileTypeJson(process.stdio_file_descriptors_at_process_creation.stdin_fd)},
                {"stdout", fileTypeJson(process.stdio_file_descriptors_at_process_creation.stdout_fd)},
                {"stderr", fileTypeJson(process.stdio_file_descriptors_at_process_creation.stderr_fd)}
            }},
            {"shell_command", process.shell_command.value}
        };
    }

    static nlohmann::json expectedFile(const owlsm::events::File& file)
    {
        return {
            {"inode", file.inode},
            {"dev", file.dev},
            {"path", file.path.value},
            {"owner", {{"uid", file.owner.uid}, {"gid", file.owner.gid}}},
            {"mode", file.mode},
            {"type", fileTypeJson(file.type)},
            {"suid", file.suid},
            {"sgid", file.sgid},
            {"last_modified_seconds", file.last_modified_seconds},
            {"nlink", file.nlink},
            {"filename", file.filename.value}
        };
    }

    static const char* fileTypeJson(file_type type)
    {
        switch (type)
        {
            case UNKNOWN_FILE_TYPE: return "UNKNOWN_FILE_TYPE";
            case DIRECTORY: return "DIRECTORY";
            case SYMLINK: return "SYMLINK";
            case BLOCK_DEVICE: return "BLOCK_DEVICE";
            case CHAR_DEVICE: return "CHAR_DEVICE";
            case REGULAR_FILE: return "REGULAR_FILE";
            case SOCKET: return "SOCKET";
            case FIFO: return "FIFO";
            case NO_FILE: return "NO_FILE";
        }
        return "";
    }
};

TEST_F(EventToJsonTest, fork_event_matches_full_document)
{
    const nlohmann::json expected = {
        {"id", EVENT_ID},
        {"type", "FORK"},
        {"action", "ALLOW_EVENT"},
        {"matched_rule_id", MATCHED_RULE_ID},
        {"had_error", HAD_ERROR},
        {"process", expectedProcess(actorProcess())},
        {"parent_process", expectedProcess(parentProcess())},
        {"time", EVENT_TIME},
        {"data", nlohmann::json::object()}
    };

    const nlohmann::json actual = serialize(makeBaseEvent());
    expectJsonEqual(actual, expected);
}

TEST_F(EventToJsonTest, chmod_data_has_target_file_and_requested_mode)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = CHMOD;

    owlsm::events::ChmodEventData chmod;
    chmod.file = chmodTargetFile();
    chmod.requested_mode = CHMOD_REQUESTED_MODE;
    event.data = chmod;

    const nlohmann::json expected = {
        {"target", {{"file", expectedFile(chmod.file)}}},
        {"chmod", {{"requested_mode", CHMOD_REQUESTED_MODE}}}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, error_matches_full_document)
{
    owlsm::events::Error error;
    error.error_code = ERROR_CODE;
    error.location = ERROR_LOCATION;
    error.details = ERROR_DETAILS;
    error.hook_name = ERROR_HOOK_NAME;
    error.is_enriched = ERROR_IS_ENRICHED;

    const nlohmann::json expected = {
        {"error_code", ERROR_CODE},
        {"location", ERROR_LOCATION},
        {"details", ERROR_DETAILS}
    };

    const nlohmann::json actual = serialize(error);
    expectJsonEqual(actual, expected);
}

TEST_F(EventToJsonTest, escaped_path_round_trips)
{
    owlsm::events::Event event = makeBaseEvent();
    event.process.file.path.value = ESCAPED_PATH;

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["process"]["file"]["path"], nlohmann::json(ESCAPED_PATH));
}

TEST_F(EventToJsonTest, matched_rule_metadata_omits_empty_fields)
{
    owlsm::events::Event event = makeBaseEvent();
    event.matched_rule_metadata.title = RULE_TITLE;
    event.matched_rule_metadata.severity = MATCHED_RULE_SEVERITY;
    event.matched_rule_metadata.mitre_tags = {RULE_MITRE_TAG_PERMISSIONS, RULE_MITRE_TAG_LINUX};

    const nlohmann::json expected = {
        {"title", RULE_TITLE},
        {"severity", "high"},
        {"mitre_tags", {RULE_MITRE_TAG_PERMISSIONS, RULE_MITRE_TAG_LINUX}}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["matched_rule_metadata"], expected);
}

TEST_F(EventToJsonTest, network_ipv4_data_formats_addresses)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = NETWORK;

    owlsm::events::NetworkEventData network;
    network.direction = NETWORK_DIRECTION;
    network.protocol = NETWORK_PROTOCOL;
    network.ip_type = NETWORK_IP_TYPE;
    network.source_port = NETWORK_SOURCE_PORT;
    network.destination_port = NETWORK_DESTINATION_PORT;

    owlsm::events::Ipv4Addresses addresses;
    addresses.source_ip = ipv4Address(NETWORK_SOURCE_IP);
    addresses.destination_ip = ipv4Address(NETWORK_DESTINATION_IP);
    network.addresses = addresses;
    event.data = network;

    const nlohmann::json expected = {
        {"network", {
            {"direction", "OUTGOING"},
            {"source_ip", NETWORK_SOURCE_IP},
            {"destination_ip", NETWORK_DESTINATION_IP},
            {"source_port", NETWORK_SOURCE_PORT},
            {"destination_port", NETWORK_DESTINATION_PORT},
            {"protocol", NETWORK_PROTOCOL},
            {"ip_type", NETWORK_IP_TYPE}
        }}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, chown_data_has_requested_owner)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = CHOWN;

    owlsm::events::ChownEventData chown;
    chown.file = chmodTargetFile();
    chown.requested_owner_uid = CHOWN_REQUESTED_UID;
    chown.requested_owner_gid = CHOWN_REQUESTED_GID;
    event.data = chown;

    const nlohmann::json expected = {
        {"target", {{"file", expectedFile(chown.file)}}},
        {"chown", {
            {"requested_owner_uid", CHOWN_REQUESTED_UID},
            {"requested_owner_gid", CHOWN_REQUESTED_GID}
        }}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, exec_data_has_target_process)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = EXEC;

    owlsm::events::ExecEventData exec;
    exec.new_process = parentProcess();
    event.data = exec;

    const nlohmann::json expected = {
        {"target", {{"process", expectedProcess(exec.new_process)}}}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, exit_data_has_exit_code_and_signal)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = EXIT;

    owlsm::events::ExitEventData exit_data;
    exit_data.exit_code = EXIT_CODE;
    exit_data.signal = EXIT_SIGNAL;
    event.data = exit_data;

    const nlohmann::json expected = {
        {"exit_code", EXIT_CODE},
        {"signal", EXIT_SIGNAL}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, generic_file_data_has_target_file)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = FILE_CREATE;

    owlsm::events::GenericFileEventData file_data;
    file_data.file = chmodTargetFile();
    event.data = file_data;

    const nlohmann::json expected = {
        {"target", {{"file", expectedFile(file_data.file)}}}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, rename_data_has_source_and_destination)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = RENAME;

    owlsm::events::RenameEventData rename;
    rename.flags = RENAME_FLAGS;
    rename.source_file = chmodTargetFile();
    rename.destination_file = actorProcess().file;
    event.data = rename;

    const nlohmann::json expected = {
        {"flags", RENAME_FLAGS},
        {"rename", {
            {"source_file", expectedFile(rename.source_file)},
            {"destination_file", expectedFile(rename.destination_file)}
        }}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, signal_data_has_target_process_and_signal)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = SIGNAL;

    owlsm::events::SignalEventData signal;
    signal.process = parentProcess();
    signal.signal = TARGET_SIGNAL;
    event.data = signal;

    const nlohmann::json expected = {
        {"target", {{"process", expectedProcess(signal.process)}}},
        {"signal", TARGET_SIGNAL}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, ptrace_data_has_target_process_and_mode)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = PTRACE;

    owlsm::events::PtraceEventData ptrace;
    ptrace.process = parentProcess();
    ptrace.mode = PTRACE_MODE;
    event.data = ptrace;

    const nlohmann::json expected = {
        {"target", {{"process", expectedProcess(ptrace.process)}}},
        {"mode", PTRACE_MODE}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, network_ipv6_data_formats_addresses)
{
    owlsm::events::Event event = makeBaseEvent();
    event.type = NETWORK;

    owlsm::events::NetworkEventData network;
    network.direction = NETWORK_V6_DIRECTION;
    network.protocol = NETWORK_PROTOCOL;
    network.ip_type = NETWORK_V6_IP_TYPE;
    network.source_port = NETWORK_SOURCE_PORT;
    network.destination_port = NETWORK_DESTINATION_PORT;

    owlsm::events::Ipv6Addresses addresses;
    ipv6Address(NETWORK_V6_SOURCE_IP, addresses.source_ip);
    ipv6Address(NETWORK_V6_DESTINATION_IP, addresses.destination_ip);
    network.addresses = addresses;
    event.data = network;

    const nlohmann::json expected = {
        {"network", {
            {"direction", "INCOMING"},
            {"source_ip", NETWORK_V6_SOURCE_IP},
            {"destination_ip", NETWORK_V6_DESTINATION_IP},
            {"source_port", NETWORK_SOURCE_PORT},
            {"destination_port", NETWORK_DESTINATION_PORT},
            {"protocol", NETWORK_PROTOCOL},
            {"ip_type", NETWORK_V6_IP_TYPE}
        }}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["data"], expected);
}

TEST_F(EventToJsonTest, empty_path_and_cmd_stay_present)
{
    owlsm::events::Event event = makeBaseEvent();
    event.process.file.path.value = EMPTY_TEXT;
    event.process.cmd.value = EMPTY_TEXT;

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["process"]["file"]["path"], nlohmann::json(EMPTY_TEXT));
    expectJsonEqual(actual["process"]["cmd"], nlohmann::json(EMPTY_TEXT));
}

TEST_F(EventToJsonTest, remaining_file_types_serialize_as_enumerator_names)
{
    owlsm::events::Event event = makeBaseEvent();
    event.process.file.type = DIRECTORY;
    event.process.stdio_file_descriptors_at_process_creation.stdin_fd = SYMLINK;
    event.process.stdio_file_descriptors_at_process_creation.stdout_fd = BLOCK_DEVICE;
    event.process.stdio_file_descriptors_at_process_creation.stderr_fd = CHAR_DEVICE;
    event.parent_process.file.type = NO_FILE;

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["process"]["file"]["type"], nlohmann::json("DIRECTORY"));
    expectJsonEqual(actual["process"]["stdio_file_descriptors_at_process_creation"]["stdin"], nlohmann::json("SYMLINK"));
    expectJsonEqual(actual["process"]["stdio_file_descriptors_at_process_creation"]["stdout"], nlohmann::json("BLOCK_DEVICE"));
    expectJsonEqual(actual["process"]["stdio_file_descriptors_at_process_creation"]["stderr"], nlohmann::json("CHAR_DEVICE"));
    expectJsonEqual(actual["parent_process"]["file"]["type"], nlohmann::json("NO_FILE"));
}

TEST_F(EventToJsonTest, action_serializes_as_enumerator_name)
{
    const std::pair<rule_action, const char*> actions[] = {
        {ALLOW_EVENT, "ALLOW_EVENT"},
        {BLOCK_EVENT, "BLOCK_EVENT"},
        {BLOCK_KILL_PROCESS, "BLOCK_KILL_PROCESS"},
        {BLOCK_KILL_PROCESS_KILL_PARENT, "BLOCK_KILL_PROCESS_KILL_PARENT"},
        {KILL_PROCESS, "KILL_PROCESS"},
        {EXCLUDE_EVENT, "EXCLUDE_EVENT"}
    };

    for (const auto& [action, name] : actions)
    {
        owlsm::events::Event event = makeBaseEvent();
        event.action = action;
        const nlohmann::json actual = serialize(event);
        expectJsonEqual(actual["action"], nlohmann::json(name));
    }
}

TEST_F(EventToJsonTest, event_type_serializes_as_enumerator_name)
{
    const std::pair<event_type, const char*> types[] = {
        {EXEC, "EXEC"},
        {FORK, "FORK"},
        {EXIT, "EXIT"},
        {FILE_CREATE, "FILE_CREATE"},
        {CHOWN, "CHOWN"},
        {CHMOD, "CHMOD"},
        {WRITE, "WRITE"},
        {READ, "READ"},
        {UNLINK, "UNLINK"},
        {RENAME, "RENAME"},
        {NETWORK, "NETWORK"},
        {MKDIR, "MKDIR"},
        {RMDIR, "RMDIR"},
        {SIGNAL, "SIGNAL"},
        {PTRACE, "PTRACE"}
    };

    for (const auto& [type, name] : types)
    {
        owlsm::events::Event event = makeBaseEvent();
        event.type = type;
        const nlohmann::json actual = serialize(event);
        expectJsonEqual(actual["type"], nlohmann::json(name));
    }
}

TEST_F(EventToJsonTest, remaining_rule_severities_serialize_as_words)
{
    const std::pair<rule_severity, const char*> severities[] = {
        {RULE_SEVERITY_INFORMATIONAL, "informational"},
        {RULE_SEVERITY_LOW, "low"},
        {RULE_SEVERITY_MEDIUM, "medium"}
    };

    for (const auto& [severity, name] : severities)
    {
        owlsm::events::Event event = makeBaseEvent();
        event.matched_rule_metadata.title = RULE_TITLE;
        event.matched_rule_metadata.severity = severity;
        const nlohmann::json actual = serialize(event);
        expectJsonEqual(actual["matched_rule_metadata"]["severity"], nlohmann::json(name));
    }
}

TEST_F(EventToJsonTest, matched_rule_metadata_emits_every_populated_field)
{
    owlsm::events::Event event = makeBaseEvent();
    event.matched_rule_metadata.description = RULE_DESCRIPTION;
    event.matched_rule_metadata.title = RULE_TITLE;
    event.matched_rule_metadata.severity = CRITICAL_RULE_SEVERITY;
    event.matched_rule_metadata.mitre_tags = {RULE_MITRE_TAG_PERMISSIONS, RULE_MITRE_TAG_LINUX};
    event.matched_rule_metadata.name = RULE_NAME;
    event.matched_rule_metadata.author = RULE_AUTHOR;
    event.matched_rule_metadata.status = RULE_STATUS;

    const nlohmann::json expected = {
        {"description", RULE_DESCRIPTION},
        {"title", RULE_TITLE},
        {"severity", "critical"},
        {"mitre_tags", {RULE_MITRE_TAG_PERMISSIONS, RULE_MITRE_TAG_LINUX}},
        {"name", RULE_NAME},
        {"author", RULE_AUTHOR},
        {"status", RULE_STATUS}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["matched_rule_metadata"], expected);
}

TEST_F(EventToJsonTest, matched_rule_metadata_omits_unknown_severity)
{
    owlsm::events::Event event = makeBaseEvent();
    event.matched_rule_metadata.title = RULE_TITLE;

    const nlohmann::json expected = {
        {"title", RULE_TITLE}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["matched_rule_metadata"], expected);
}

TEST_F(EventToJsonTest, out_of_range_rule_severity_serializes_as_unknown)
{
    owlsm::events::Event event = makeBaseEvent();
    event.matched_rule_metadata.title = RULE_TITLE;
    event.matched_rule_metadata.severity = INVALID_RULE_SEVERITY;

    const nlohmann::json expected = {
        {"title", RULE_TITLE},
        {"severity", "unknown"}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["matched_rule_metadata"], expected);
}

TEST_F(EventToJsonTest, error_keeps_empty_location_and_details)
{
    owlsm::events::Error error;
    error.error_code = EMPTY_ERROR_CODE;
    error.location = EMPTY_TEXT;
    error.details = EMPTY_TEXT;
    error.hook_name = ERROR_HOOK_NAME;
    error.is_enriched = ERROR_IS_ENRICHED;

    const nlohmann::json expected = {
        {"error_code", EMPTY_ERROR_CODE},
        {"location", EMPTY_TEXT},
        {"details", EMPTY_TEXT}
    };

    const nlohmann::json actual = serialize(error);
    expectJsonEqual(actual, expected);
}

TEST_F(EventToJsonTest, multiple_events_are_separate_json_lines)
{
    owlsm::events::Event first = makeBaseEvent();
    owlsm::events::Event second = makeBaseEvent();
    second.id = SECOND_EVENT_ID;

    owlsm::events::EventToJson<owlsm::events::Event> serializer;
    const std::vector<std::shared_ptr<owlsm::events::Event>> messages{
        shareEvent(std::move(first)),
        shareEvent(std::move(second))
    };
    const std::string output = render(serializer, messages);
    ASSERT_FALSE(output.empty());
    EXPECT_EQ(output.back(), '\n');

    const std::vector<nlohmann::json> documents = parseDocuments(output);
    ASSERT_EQ(documents.size(), 2u);
    expectJsonEqual(documents[0]["id"], nlohmann::json(EVENT_ID));
    expectJsonEqual(documents[1]["id"], nlohmann::json(SECOND_EVENT_ID));
}

TEST_F(EventToJsonTest, build_output_buffer_replaces_previous_output)
{
    owlsm::events::Event first = makeBaseEvent();
    owlsm::events::Event second = makeBaseEvent();
    second.id = SECOND_EVENT_ID;

    owlsm::events::EventToJson<owlsm::events::Event> serializer;
    const std::vector<std::shared_ptr<owlsm::events::Event>> both{
        shareEvent(first),
        shareEvent(second)
    };
    render(serializer, both);

    const std::vector<std::shared_ptr<owlsm::events::Event>> only_second{
        shareEvent(std::move(second))
    };
    const std::vector<nlohmann::json> documents = parseDocuments(render(serializer, only_second));
    ASSERT_EQ(documents.size(), 1u);
    expectJsonEqual(documents[0]["id"], nlohmann::json(SECOND_EVENT_ID));
}

TEST_F(EventToJsonTest, empty_message_list_produces_no_documents)
{
    owlsm::events::EventToJson<owlsm::events::Event> serializer;
    const std::vector<std::shared_ptr<owlsm::events::Event>> messages;
    const std::vector<nlohmann::json> documents = parseDocuments(render(serializer, messages));
    EXPECT_EQ(documents.size(), 0u);
}

TEST_F(EventToJsonTest, invalid_utf8_event_is_skipped_and_following_event_remains)
{
    owlsm::events::Event broken = makeBaseEvent();
    broken.process.file.path.value = INVALID_UTF8_PATH;
    owlsm::events::Event valid = makeBaseEvent();
    valid.id = SECOND_EVENT_ID;

    owlsm::events::EventToJson<owlsm::events::Event> serializer;
    const std::vector<std::shared_ptr<owlsm::events::Event>> messages{
        shareEvent(std::move(broken)),
        shareEvent(std::move(valid))
    };
    const std::vector<nlohmann::json> documents = parseDocuments(render(serializer, messages));
    ASSERT_EQ(documents.size(), 1u);
    expectJsonEqual(documents[0]["id"], nlohmann::json(SECOND_EVENT_ID));
    expectJsonEqual(documents[0]["process"]["file"]["path"], nlohmann::json(ACTOR_PATH));
}

TEST_F(EventToJsonTest, kubernetes_pod_fields_are_emitted)
{
    owlsm::events::Event event = makeBaseEvent();
    event.kubernetes.pod_uid = K8S_POD_UID;
    event.kubernetes.pod_namespace = K8S_POD_NAMESPACE;
    event.kubernetes.pod_name = K8S_POD_NAME;
    event.kubernetes.pod_labels.emplace(K8S_LABEL_APP, K8S_LABEL_APP_VALUE);
    event.kubernetes.pod_labels.emplace(K8S_LABEL_TIER, K8S_LABEL_TIER_VALUE);
    event.kubernetes.host_event = K8S_HOST_EVENT;

    const nlohmann::json expected = {
        {"pod_uid", K8S_POD_UID},
        {"pod_namespace", K8S_POD_NAMESPACE},
        {"pod_name", K8S_POD_NAME},
        {"pod_labels", {
            {K8S_LABEL_APP, K8S_LABEL_APP_VALUE},
            {K8S_LABEL_TIER, K8S_LABEL_TIER_VALUE}
        }},
        {"host_event", K8S_HOST_EVENT}
    };

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["kubernetes"], expected);
}

TEST_F(EventToJsonTest, unnamed_file_type_serializes_as_unknown_file_type)
{
    owlsm::events::Event event = makeBaseEvent();
    event.process.file.type = UNNAMED_FILE_TYPE;

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["process"]["file"]["type"], nlohmann::json("UNKNOWN_FILE_TYPE"));
}

TEST_F(EventToJsonTest, utf8_path_round_trips)
{
    owlsm::events::Event event = makeBaseEvent();
    event.process.file.path.value = UTF8_PATH;

    const nlohmann::json actual = serialize(event);
    expectJsonEqual(actual["process"]["file"]["path"], nlohmann::json(UTF8_PATH));
}
