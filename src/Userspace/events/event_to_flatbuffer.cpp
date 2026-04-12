#include "events/event_to_flatbuffer.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <cstring>

namespace owlsm::events
{

template <typename MessageType>
EventToFlatbuffer<MessageType>::EventToFlatbuffer() : m_builder(1024)
{
    m_bulk_buffer.reserve(1024 * 1024);
}

template <typename MessageType>
void EventToFlatbuffer<MessageType>::buildOutputBuffer(const std::vector<std::shared_ptr<MessageType>>& messages)
{
    m_bulk_buffer.clear();
    for (const auto& msg : messages)
    {
        try
        {
            m_builder.Clear();
            serializeMessage(*msg);

            auto* buf = m_builder.GetBufferPointer();
            auto buf_size = m_builder.GetSize();
            m_bulk_buffer.insert(m_bulk_buffer.end(), buf, buf + buf_size);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("Failed to serialize message to FlatBuffer: " << e.what());
        }
    }
}

template <typename MessageType>
const void* EventToFlatbuffer<MessageType>::data() const
{
    return m_bulk_buffer.data();
}

template <typename MessageType>
size_t EventToFlatbuffer<MessageType>::size() const
{
    return m_bulk_buffer.size();
}

template <typename MessageType>
std::string EventToFlatbuffer<MessageType>::ipv4ToString(uint32_t be_addr)
{
    char buf[INET_ADDRSTRLEN] = {0};
    in_addr a{};
    a.s_addr = be_addr;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    return buf;
}

template <typename MessageType>
std::string EventToFlatbuffer<MessageType>::ipv6ToString(const unsigned int bytes[4])
{
    char buf[INET6_ADDRSTRLEN] = {0};
    in6_addr a6{};
    std::memcpy(a6.s6_addr, bytes, sizeof(a6.s6_addr));
    inet_ntop(AF_INET6, &a6, buf, sizeof(buf));
    return buf;
}

template <typename MessageType>
fb::FileType EventToFlatbuffer<MessageType>::toFbFileType(file_type ft)
{
    switch (ft)
    {
        case UNKNOWN_FILE_TYPE: return fb::FileType::UNKNOWN_FILE_TYPE;
        case DIRECTORY:         return fb::FileType::DIRECTORY;
        case SYMLINK:           return fb::FileType::SYMLINK;
        case BLOCK_DEVICE:      return fb::FileType::BLOCK_DEVICE;
        case CHAR_DEVICE:       return fb::FileType::CHAR_DEVICE;
        case REGULAR_FILE:      return fb::FileType::REGULAR_FILE;
        case SOCKET:            return fb::FileType::SOCKET;
        case FIFO:              return fb::FileType::FIFO;
        case NO_FILE:           return fb::FileType::NO_FILE;
        default:                return fb::FileType::UNKNOWN_FILE_TYPE;
    }
}

template <typename MessageType>
fb::EventType EventToFlatbuffer<MessageType>::toFbEventType(event_type et)
{
    switch (et)
    {
        case EXEC:        return fb::EventType::EXEC;
        case FORK:        return fb::EventType::FORK;
        case EXIT:        return fb::EventType::EXIT;
        case FILE_CREATE: return fb::EventType::FILE_CREATE;
        case UNLINK:      return fb::EventType::UNLINK;
        case MKDIR:       return fb::EventType::MKDIR;
        case RMDIR:       return fb::EventType::RMDIR;
        case CHMOD:       return fb::EventType::CHMOD;
        case CHOWN:       return fb::EventType::CHOWN;
        case WRITE:       return fb::EventType::WRITE;
        case READ:        return fb::EventType::READ;
        case RENAME:      return fb::EventType::RENAME;
        case NETWORK:     return fb::EventType::NETWORK;
        default:          return fb::EventType::EXEC;
    }
}

template <typename MessageType>
fb::Action EventToFlatbuffer<MessageType>::toFbAction(rule_action a)
{
    switch (a)
    {
        case ALLOW_EVENT:                    return fb::Action::ALLOW_EVENT;
        case BLOCK_EVENT:                    return fb::Action::BLOCK_EVENT;
        case BLOCK_KILL_PROCESS:             return fb::Action::BLOCK_KILL_PROCESS;
        case BLOCK_KILL_PROCESS_KILL_PARENT: return fb::Action::BLOCK_KILL_PROCESS_KILL_PARENT;
        case KILL_PROCESS:                   return fb::Action::KILL_PROCESS;
        case EXCLUDE_EVENT:                  return fb::Action::EXCLUDE_EVENT;
        default:                             return fb::Action::ALLOW_EVENT;
    }
}

template <typename MessageType>
flatbuffers::Offset<fb::File> EventToFlatbuffer<MessageType>::serializeFile(
    flatbuffers::FlatBufferBuilder& builder, const File& f)
{
    auto path_off = builder.CreateString(f.path.value);
    auto filename_off = builder.CreateString(f.filename.value);
    fb::Owner owner(f.owner.uid, f.owner.gid);

    return fb::CreateFile(
        builder, f.inode, f.dev, path_off, &owner, f.mode,
        toFbFileType(f.type), f.suid, f.sgid,
        f.last_modified_seconds, f.nlink, filename_off);
}

template <typename MessageType>
flatbuffers::Offset<fb::Process> EventToFlatbuffer<MessageType>::serializeProcess(
    flatbuffers::FlatBufferBuilder& builder, const Process& p)
{
    auto file_off = serializeFile(builder, p.file);
    auto cmd_off = builder.CreateString(p.cmd.value);
    auto shell_cmd_off = builder.CreateString(p.shell_command.value);

    fb::StdioFileDescriptors stdio(
        toFbFileType(p.stdio_file_descriptors_at_process_creation.stdin_fd),
        toFbFileType(p.stdio_file_descriptors_at_process_creation.stdout_fd),
        toFbFileType(p.stdio_file_descriptors_at_process_creation.stderr_fd));

    fb::ProcessBuilder pb(builder);
    pb.add_pid(p.pid);
    pb.add_ppid(p.ppid);
    pb.add_ruid(p.ruid);
    pb.add_rgid(p.rgid);
    pb.add_euid(p.euid);
    pb.add_egid(p.egid);
    pb.add_suid(p.suid);
    pb.add_cgroup_id(p.cgroup_id);
    pb.add_start_time(p.start_time);
    pb.add_ptrace_flags(p.ptrace_flags);
    pb.add_file(file_off);
    pb.add_cmd(cmd_off);
    pb.add_stdio_file_descriptors_at_process_creation(&stdio);
    pb.add_shell_command(shell_cmd_off);
    return pb.Finish();
}

template <typename MessageType>
void EventToFlatbuffer<MessageType>::serializeEvent(const Event& ev)
{
    auto process_off = serializeProcess(m_builder, ev.process);
    auto parent_off = serializeProcess(m_builder, ev.parent_process);

    flatbuffers::Offset<fb::RuleMetadata> meta_off = 0;
    if (ev.matched_rule_id > 0)
    {
        auto desc_off = m_builder.CreateString(ev.matched_rule_metadata.description);
        meta_off = fb::CreateRuleMetadata(m_builder, desc_off);
    }

    fb::EventData data_type = fb::EventData::NONE;
    flatbuffers::Offset<void> data_off = 0;

    std::visit([&](const auto& d) {
        using T = std::decay_t<decltype(d)>;

        if constexpr (std::is_same_v<T, GenericFileEventData>)
        {
            auto file_off = serializeFile(m_builder, d.file);
            auto target_off = fb::CreateTarget(m_builder, file_off, 0);
            data_type = fb::EventData::GenericFileEventData;
            data_off = fb::CreateGenericFileEventData(m_builder, target_off).Union();
        }
        else if constexpr (std::is_same_v<T, ChownEventData>)
        {
            auto file_off = serializeFile(m_builder, d.file);
            auto target_off = fb::CreateTarget(m_builder, file_off, 0);
            auto chown_info_off = fb::CreateChownInfo(m_builder, d.requested_owner_uid, d.requested_owner_gid);
            data_type = fb::EventData::ChownEventData;
            data_off = fb::CreateChownEventData(m_builder, target_off, chown_info_off).Union();
        }
        else if constexpr (std::is_same_v<T, ChmodEventData>)
        {
            auto file_off = serializeFile(m_builder, d.file);
            auto target_off = fb::CreateTarget(m_builder, file_off, 0);
            auto chmod_info_off = fb::CreateChmodInfo(m_builder, d.requested_mode);
            data_type = fb::EventData::ChmodEventData;
            data_off = fb::CreateChmodEventData(m_builder, target_off, chmod_info_off).Union();
        }
        else if constexpr (std::is_same_v<T, ExecEventData>)
        {
            auto proc_off = serializeProcess(m_builder, d.new_process);
            auto target_off = fb::CreateTarget(m_builder, 0, proc_off);
            data_type = fb::EventData::ExecEventData;
            data_off = fb::CreateExecEventData(m_builder, target_off).Union();
        }
        else if constexpr (std::is_same_v<T, ForkEventData>)
        {
            data_type = fb::EventData::ForkEventData;
            data_off = fb::CreateForkEventData(m_builder).Union();
        }
        else if constexpr (std::is_same_v<T, ExitEventData>)
        {
            data_type = fb::EventData::ExitEventData;
            data_off = fb::CreateExitEventData(m_builder, d.exit_code, d.signal).Union();
        }
        else if constexpr (std::is_same_v<T, RenameEventData>)
        {
            auto src_off = serializeFile(m_builder, d.source_file);
            auto dst_off = serializeFile(m_builder, d.destination_file);
            auto rename_info_off = fb::CreateRenameInfo(m_builder, src_off, dst_off);
            data_type = fb::EventData::RenameEventData;
            data_off = fb::CreateRenameEventData(m_builder, d.flags, rename_info_off).Union();
        }
        else if constexpr (std::is_same_v<T, NetworkEventData>)
        {
            std::string src_ip, dst_ip;
            if (d.ip_type == AF_INET)
            {
                const auto& ipv4 = std::get<Ipv4Addresses>(d.addresses);
                src_ip = ipv4ToString(ipv4.source_ip);
                dst_ip = ipv4ToString(ipv4.destination_ip);
            }
            else
            {
                const auto& ipv6 = std::get<Ipv6Addresses>(d.addresses);
                src_ip = ipv6ToString(ipv6.source_ip);
                dst_ip = ipv6ToString(ipv6.destination_ip);
            }

            auto direction = (d.direction == INCOMING)
                ? fb::ConnectionDirection::INCOMING
                : fb::ConnectionDirection::OUTGOING;

            auto src_ip_off = m_builder.CreateString(src_ip);
            auto dst_ip_off = m_builder.CreateString(dst_ip);
            auto network_info_off = fb::CreateNetworkInfo(m_builder, direction,
                src_ip_off, dst_ip_off, d.source_port, d.destination_port,
                d.protocol, d.ip_type);
            data_type = fb::EventData::NetworkEventData;
            data_off = fb::CreateNetworkEventData(m_builder, network_info_off).Union();
        }
    }, ev.data);

    auto event_off = fb::CreateEvent(m_builder, ev.id,
        toFbEventType(ev.type), toFbAction(ev.action),
        ev.matched_rule_id, meta_off, ev.had_error_while_handling,
        process_off, parent_off, ev.time,
        data_type, data_off);

    m_builder.FinishSizePrefixed(event_off);
}

template <typename MessageType>
void EventToFlatbuffer<MessageType>::serializeError(const Error& err)
{
    auto loc_off = m_builder.CreateString(err.location);
    auto det_off = m_builder.CreateString(err.details);
    auto hook_off = m_builder.CreateString(err.hook_name);
    auto error_off = fb::CreateError(m_builder, err.error_code, loc_off, det_off, hook_off);
    m_builder.FinishSizePrefixed(error_off);
}

template <typename MessageType>
void EventToFlatbuffer<MessageType>::serializeMessage(const Event& ev)
{
    serializeEvent(ev);
}

template <typename MessageType>
void EventToFlatbuffer<MessageType>::serializeMessage(const Error& err)
{
    serializeError(err);
}

template class EventToFlatbuffer<Event>;
template class EventToFlatbuffer<Error>;

}
