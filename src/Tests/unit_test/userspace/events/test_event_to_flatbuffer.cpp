#include <gtest/gtest.h>
#include "events/event_to_flatbuffer.hpp"
#include "events/flatbuffers/include/owlsm_events_generated.h"

#include <flatbuffers/flatbuffers.h>
#include <memory>
#include <vector>
#include <netinet/in.h>

class EventToFlatbufferTest : public ::testing::Test
{
protected:
    owlsm::events::EventToFlatbuffer<owlsm::events::Event> m_event_serializer;
    owlsm::events::EventToFlatbuffer<owlsm::events::Error> m_error_serializer;

    static std::shared_ptr<owlsm::events::Event> makeBaseEvent(
        event_type type, unsigned long long id = 1)
    {
        auto ev = std::make_shared<owlsm::events::Event>();
        ev->id = id;
        ev->type = type;
        ev->action = ALLOW_EVENT;
        ev->had_error_while_handling = 0;
        ev->time = 123456789;
        ev->process.pid = 1000;
        ev->process.ppid = 999;
        ev->process.ruid = 0;
        ev->process.euid = 0;
        ev->process.file.path.value = "/usr/bin/test";
        ev->process.file.filename.value = "test";
        ev->process.cmd.value = "/usr/bin/test --flag";
        ev->process.shell_command.value = "";
        ev->parent_process.pid = 999;
        ev->parent_process.ppid = 1;
        ev->parent_process.file.path.value = "/bin/bash";
        ev->parent_process.file.filename.value = "bash";
        ev->parent_process.cmd.value = "/bin/bash";
        ev->parent_process.shell_command.value = "";
        return ev;
    }

    static const owlsm::fb::Event* getSizePrefixedEvent(const void* buf)
    {
        return flatbuffers::GetSizePrefixedRoot<owlsm::fb::Event>(buf);
    }

    static const owlsm::fb::Error* getSizePrefixedError(const void* buf)
    {
        return flatbuffers::GetSizePrefixedRoot<owlsm::fb::Error>(buf);
    }
};

TEST_F(EventToFlatbufferTest, fork_event_serialization)
{
    auto ev = makeBaseEvent(FORK);
    ev->data = owlsm::events::ForkEventData{};

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    ASSERT_GT(m_event_serializer.size(), 0u);
    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    ASSERT_NE(fb_ev, nullptr);
    EXPECT_EQ(fb_ev->id(), 1u);
    EXPECT_EQ(fb_ev->type(), owlsm::fb::EventType::FORK);
    EXPECT_EQ(fb_ev->action(), owlsm::fb::Action::ALLOW_EVENT);
    EXPECT_EQ(fb_ev->time(), 123456789u);
    EXPECT_EQ(fb_ev->data_type(), owlsm::fb::EventData::ForkEventData);

    ASSERT_NE(fb_ev->process(), nullptr);
    EXPECT_EQ(fb_ev->process()->pid(), 1000u);
    EXPECT_EQ(fb_ev->process()->ppid(), 999u);
    ASSERT_NE(fb_ev->process()->file(), nullptr);
    EXPECT_STREQ(fb_ev->process()->file()->path()->c_str(), "/usr/bin/test");
    EXPECT_STREQ(fb_ev->process()->cmd()->c_str(), "/usr/bin/test --flag");

    ASSERT_NE(fb_ev->parent_process(), nullptr);
    EXPECT_EQ(fb_ev->parent_process()->pid(), 999u);
}

TEST_F(EventToFlatbufferTest, exec_event_with_new_process)
{
    auto ev = makeBaseEvent(EXEC, 42);
    owlsm::events::ExecEventData exec_data;
    exec_data.new_process.pid = 2000;
    exec_data.new_process.ppid = 1000;
    exec_data.new_process.file.path.value = "/usr/bin/curl";
    exec_data.new_process.file.filename.value = "curl";
    exec_data.new_process.cmd.value = "curl https://example.com";
    exec_data.new_process.shell_command.value = "";
    ev->data = exec_data;

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    ASSERT_NE(fb_ev, nullptr);
    EXPECT_EQ(fb_ev->id(), 42u);
    EXPECT_EQ(fb_ev->type(), owlsm::fb::EventType::EXEC);
    EXPECT_EQ(fb_ev->data_type(), owlsm::fb::EventData::ExecEventData);

    const auto* exec = fb_ev->data_as_ExecEventData();
    ASSERT_NE(exec, nullptr);
    ASSERT_NE(exec->target(), nullptr);
    ASSERT_NE(exec->target()->process(), nullptr);
    EXPECT_EQ(exec->target()->process()->pid(), 2000u);
    EXPECT_STREQ(exec->target()->process()->file()->path()->c_str(), "/usr/bin/curl");
    EXPECT_STREQ(exec->target()->process()->cmd()->c_str(), "curl https://example.com");
}

TEST_F(EventToFlatbufferTest, exit_event_with_exit_code_and_signal)
{
    auto ev = makeBaseEvent(EXIT, 10);
    owlsm::events::ExitEventData exit_data;
    exit_data.exit_code = 137;
    exit_data.signal = 9;
    ev->data = exit_data;

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    ASSERT_NE(fb_ev, nullptr);
    EXPECT_EQ(fb_ev->type(), owlsm::fb::EventType::EXIT);
    EXPECT_EQ(fb_ev->data_type(), owlsm::fb::EventData::ExitEventData);

    const auto* exit_d = fb_ev->data_as_ExitEventData();
    ASSERT_NE(exit_d, nullptr);
    EXPECT_EQ(exit_d->exit_code(), 137u);
    EXPECT_EQ(exit_d->signal(), 9u);
}

TEST_F(EventToFlatbufferTest, chmod_event_with_file_details)
{
    auto ev = makeBaseEvent(CHMOD, 5);
    owlsm::events::ChmodEventData chmod_data;
    chmod_data.file.inode = 12345;
    chmod_data.file.dev = 42;
    chmod_data.file.path.value = "/etc/shadow";
    chmod_data.file.filename.value = "shadow";
    chmod_data.file.owner.uid = 0;
    chmod_data.file.owner.gid = 0;
    chmod_data.file.mode = 0640;
    chmod_data.file.type = REGULAR_FILE;
    chmod_data.file.suid = 0;
    chmod_data.file.sgid = 0;
    chmod_data.file.last_modified_seconds = 999999;
    chmod_data.file.nlink = 1;
    chmod_data.requested_mode = 0777;
    ev->data = chmod_data;

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    ASSERT_NE(fb_ev, nullptr);
    EXPECT_EQ(fb_ev->type(), owlsm::fb::EventType::CHMOD);
    EXPECT_EQ(fb_ev->data_type(), owlsm::fb::EventData::ChmodEventData);

    const auto* chmod = fb_ev->data_as_ChmodEventData();
    ASSERT_NE(chmod, nullptr);
    ASSERT_NE(chmod->target(), nullptr);
    ASSERT_NE(chmod->target()->file(), nullptr);
    EXPECT_EQ(chmod->target()->file()->inode(), 12345u);
    EXPECT_EQ(chmod->target()->file()->dev(), 42u);
    EXPECT_STREQ(chmod->target()->file()->path()->c_str(), "/etc/shadow");
    EXPECT_STREQ(chmod->target()->file()->filename()->c_str(), "shadow");
    ASSERT_NE(chmod->target()->file()->owner(), nullptr);
    EXPECT_EQ(chmod->target()->file()->owner()->uid(), 0u);
    EXPECT_EQ(chmod->target()->file()->owner()->gid(), 0u);
    EXPECT_EQ(chmod->target()->file()->mode(), 0640u);
    EXPECT_EQ(chmod->target()->file()->type(), owlsm::fb::FileType::REGULAR_FILE);
    EXPECT_EQ(chmod->target()->file()->last_modified_seconds(), 999999u);
    EXPECT_EQ(chmod->target()->file()->nlink(), 1u);
    ASSERT_NE(chmod->chmod(), nullptr);
    EXPECT_EQ(chmod->chmod()->requested_mode(), 0777);
}

TEST_F(EventToFlatbufferTest, chown_event)
{
    auto ev = makeBaseEvent(CHOWN, 6);
    owlsm::events::ChownEventData chown_data;
    chown_data.file.path.value = "/tmp/testfile";
    chown_data.file.filename.value = "testfile";
    chown_data.requested_owner_uid = 1000;
    chown_data.requested_owner_gid = 1000;
    ev->data = chown_data;

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    EXPECT_EQ(fb_ev->data_type(), owlsm::fb::EventData::ChownEventData);
    const auto* chown = fb_ev->data_as_ChownEventData();
    ASSERT_NE(chown, nullptr);
    ASSERT_NE(chown->target(), nullptr);
    ASSERT_NE(chown->target()->file(), nullptr);
    EXPECT_STREQ(chown->target()->file()->path()->c_str(), "/tmp/testfile");
    ASSERT_NE(chown->chown(), nullptr);
    EXPECT_EQ(chown->chown()->requested_owner_uid(), 1000u);
    EXPECT_EQ(chown->chown()->requested_owner_gid(), 1000u);
}

TEST_F(EventToFlatbufferTest, rename_event)
{
    auto ev = makeBaseEvent(RENAME, 7);
    owlsm::events::RenameEventData rename_data;
    rename_data.flags = 0;
    rename_data.source_file.path.value = "/tmp/old_name";
    rename_data.source_file.filename.value = "old_name";
    rename_data.destination_file.path.value = "/tmp/new_name";
    rename_data.destination_file.filename.value = "new_name";
    ev->data = rename_data;

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    EXPECT_EQ(fb_ev->data_type(), owlsm::fb::EventData::RenameEventData);
    const auto* ren = fb_ev->data_as_RenameEventData();
    ASSERT_NE(ren, nullptr);
    EXPECT_EQ(ren->flags(), 0u);
    ASSERT_NE(ren->rename(), nullptr);
    EXPECT_STREQ(ren->rename()->source_file()->path()->c_str(), "/tmp/old_name");
    EXPECT_STREQ(ren->rename()->destination_file()->path()->c_str(), "/tmp/new_name");
}

TEST_F(EventToFlatbufferTest, generic_file_event_write)
{
    auto ev = makeBaseEvent(WRITE, 8);
    owlsm::events::GenericFileEventData file_data;
    file_data.file.path.value = "/var/log/syslog";
    file_data.file.filename.value = "syslog";
    file_data.file.type = REGULAR_FILE;
    ev->data = file_data;

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    EXPECT_EQ(fb_ev->type(), owlsm::fb::EventType::WRITE);
    EXPECT_EQ(fb_ev->data_type(), owlsm::fb::EventData::GenericFileEventData);
    const auto* gf = fb_ev->data_as_GenericFileEventData();
    ASSERT_NE(gf, nullptr);
    ASSERT_NE(gf->target(), nullptr);
    ASSERT_NE(gf->target()->file(), nullptr);
    EXPECT_STREQ(gf->target()->file()->path()->c_str(), "/var/log/syslog");
}

TEST_F(EventToFlatbufferTest, network_event_ipv4)
{
    auto ev = makeBaseEvent(NETWORK, 9);
    owlsm::events::NetworkEventData net_data;
    net_data.direction = OUTGOING;
    net_data.protocol = 6;
    net_data.ip_type = AF_INET;
    net_data.source_port = 12345;
    net_data.destination_port = 443;
    owlsm::events::Ipv4Addresses ipv4;
    ipv4.source_ip = htonl(0x0A000001);
    ipv4.destination_ip = htonl(0xC0A80001);
    net_data.addresses = ipv4;
    ev->data = net_data;

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    EXPECT_EQ(fb_ev->type(), owlsm::fb::EventType::NETWORK);
    EXPECT_EQ(fb_ev->data_type(), owlsm::fb::EventData::NetworkEventData);
    const auto* net = fb_ev->data_as_NetworkEventData();
    ASSERT_NE(net, nullptr);
    ASSERT_NE(net->network(), nullptr);
    EXPECT_EQ(net->network()->direction(), owlsm::fb::ConnectionDirection::OUTGOING);
    EXPECT_EQ(net->network()->protocol(), 6u);
    EXPECT_EQ(net->network()->source_port(), 12345u);
    EXPECT_EQ(net->network()->destination_port(), 443u);
    EXPECT_STREQ(net->network()->source_ip()->c_str(), "10.0.0.1");
    EXPECT_STREQ(net->network()->destination_ip()->c_str(), "192.168.0.1");
}

TEST_F(EventToFlatbufferTest, event_with_matched_rule)
{
    auto ev = makeBaseEvent(CHMOD, 20);
    ev->action = BLOCK_EVENT;
    ev->matched_rule_id = 100;
    ev->matched_rule_metadata.description = "Test rule: block shadow chmod";
    ev->data = owlsm::events::ChmodEventData{};

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    EXPECT_EQ(fb_ev->action(), owlsm::fb::Action::BLOCK_EVENT);
    EXPECT_EQ(fb_ev->matched_rule_id(), 100u);
    ASSERT_NE(fb_ev->matched_rule_metadata(), nullptr);
    EXPECT_STREQ(fb_ev->matched_rule_metadata()->description()->c_str(),
        "Test rule: block shadow chmod");
}

TEST_F(EventToFlatbufferTest, error_serialization)
{
    auto err = std::make_shared<owlsm::events::Error>();
    err->error_code = -5;
    err->location = "on_chmod_handler";
    err->details = "Failed to read file metadata";
    err->hook_name = "lsm_chmod";

    std::vector<std::shared_ptr<owlsm::events::Error>> msgs = {err};
    m_error_serializer.buildOutputBuffer(msgs);

    ASSERT_GT(m_error_serializer.size(), 0u);
    const auto* fb_err = getSizePrefixedError(m_error_serializer.data());
    ASSERT_NE(fb_err, nullptr);
    EXPECT_EQ(fb_err->error_code(), -5);
    EXPECT_STREQ(fb_err->location()->c_str(), "on_chmod_handler");
    EXPECT_STREQ(fb_err->details()->c_str(), "Failed to read file metadata");
    EXPECT_STREQ(fb_err->hook_name()->c_str(), "lsm_chmod");
}

TEST_F(EventToFlatbufferTest, multiple_events_bulk_serialization)
{
    std::vector<std::shared_ptr<owlsm::events::Event>> msgs;
    for (unsigned long long i = 0; i < 5; ++i)
    {
        auto ev = makeBaseEvent(FORK, i + 100);
        ev->data = owlsm::events::ForkEventData{};
        msgs.push_back(ev);
    }

    m_event_serializer.buildOutputBuffer(msgs);
    ASSERT_GT(m_event_serializer.size(), 0u);

    const auto* ptr = static_cast<const uint8_t*>(m_event_serializer.data());
    size_t remaining = m_event_serializer.size();
    int count = 0;
    while (remaining > sizeof(uint32_t))
    {
        uint32_t msg_size;
        memcpy(&msg_size, ptr, sizeof(uint32_t));
        ASSERT_LE(msg_size + sizeof(uint32_t), remaining);

        const auto* fb_ev = flatbuffers::GetSizePrefixedRoot<owlsm::fb::Event>(ptr);
        ASSERT_NE(fb_ev, nullptr);
        EXPECT_EQ(fb_ev->id(), static_cast<uint64_t>(100 + count));
        EXPECT_EQ(fb_ev->type(), owlsm::fb::EventType::FORK);

        ptr += sizeof(uint32_t) + msg_size;
        remaining -= sizeof(uint32_t) + msg_size;
        ++count;
    }
    EXPECT_EQ(count, 5);
    EXPECT_EQ(remaining, 0u);
}

TEST_F(EventToFlatbufferTest, builder_reuse_produces_valid_output)
{
    for (int round = 0; round < 3; ++round)
    {
        auto ev = makeBaseEvent(FORK, round + 1);
        ev->data = owlsm::events::ForkEventData{};
        std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};

        m_event_serializer.buildOutputBuffer(msgs);
        ASSERT_GT(m_event_serializer.size(), 0u);

        const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
        ASSERT_NE(fb_ev, nullptr);
        EXPECT_EQ(fb_ev->id(), static_cast<uint64_t>(round + 1));
    }
}

TEST_F(EventToFlatbufferTest, process_stdio_descriptors)
{
    auto ev = makeBaseEvent(FORK, 50);
    ev->process.stdio_file_descriptors_at_process_creation.stdin_fd = REGULAR_FILE;
    ev->process.stdio_file_descriptors_at_process_creation.stdout_fd = FIFO;
    ev->process.stdio_file_descriptors_at_process_creation.stderr_fd = SOCKET;
    ev->data = owlsm::events::ForkEventData{};

    std::vector<std::shared_ptr<owlsm::events::Event>> msgs = {ev};
    m_event_serializer.buildOutputBuffer(msgs);

    const auto* fb_ev = getSizePrefixedEvent(m_event_serializer.data());
    ASSERT_NE(fb_ev->process(), nullptr);
    const auto* stdio = fb_ev->process()->stdio_file_descriptors_at_process_creation();
    ASSERT_NE(stdio, nullptr);
    EXPECT_EQ(stdio->stdin(), owlsm::fb::FileType::REGULAR_FILE);
    EXPECT_EQ(stdio->stdout(), owlsm::fb::FileType::FIFO);
    EXPECT_EQ(stdio->stderr(), owlsm::fb::FileType::SOCKET);
}
