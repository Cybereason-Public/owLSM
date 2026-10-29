#include "events/event_to_json.hpp"
#include "logger.hpp"

#include <3rd_party/yyjson/yyjson.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <new>
#include <string_view>
#include <type_traits>
#include <variant>

namespace owlsm::events
{

struct FileSlots
{
    yyjson_mut_val* inode = nullptr;
    yyjson_mut_val* dev = nullptr;
    yyjson_mut_val* path = nullptr;
    yyjson_mut_val* owner_uid = nullptr;
    yyjson_mut_val* owner_gid = nullptr;
    yyjson_mut_val* mode = nullptr;
    yyjson_mut_val* type = nullptr;
    yyjson_mut_val* suid = nullptr;
    yyjson_mut_val* sgid = nullptr;
    yyjson_mut_val* last_modified_seconds = nullptr;
    yyjson_mut_val* nlink = nullptr;
    yyjson_mut_val* filename = nullptr;
};

struct ProcessSlots
{
    yyjson_mut_val* pid = nullptr;
    yyjson_mut_val* ns_pid = nullptr;
    yyjson_mut_val* ppid = nullptr;
    yyjson_mut_val* ns_ppid = nullptr;
    yyjson_mut_val* ruid = nullptr;
    yyjson_mut_val* rgid = nullptr;
    yyjson_mut_val* euid = nullptr;
    yyjson_mut_val* egid = nullptr;
    yyjson_mut_val* suid = nullptr;
    yyjson_mut_val* cgroup_id = nullptr;
    yyjson_mut_val* start_time = nullptr;
    yyjson_mut_val* ptrace_flags = nullptr;
    FileSlots file;
    yyjson_mut_val* cmd = nullptr;
    yyjson_mut_val* stdin_fd = nullptr;
    yyjson_mut_val* stdout_fd = nullptr;
    yyjson_mut_val* stderr_fd = nullptr;
    yyjson_mut_val* shell_command = nullptr;
};

struct CommonSlots
{
    yyjson_mut_val* id = nullptr;
    yyjson_mut_val* type = nullptr;
    yyjson_mut_val* action = nullptr;
    yyjson_mut_val* matched_rule_id = nullptr;
    yyjson_mut_val* had_error = nullptr;
    ProcessSlots process;
    ProcessSlots parent_process;
    yyjson_mut_val* time = nullptr;
};

struct ChownSlots
{
    FileSlots file;
    yyjson_mut_val* uid = nullptr;
    yyjson_mut_val* gid = nullptr;
};

struct ChmodSlots
{
    FileSlots file;
    yyjson_mut_val* mode = nullptr;
};

struct ForkSlots
{
};

struct ExecSlots
{
    ProcessSlots process;
};

struct ExitSlots
{
    yyjson_mut_val* exit_code = nullptr;
    yyjson_mut_val* signal = nullptr;
};

struct GenericFileSlots
{
    FileSlots file;
};

struct RenameSlots
{
    yyjson_mut_val* flags = nullptr;
    FileSlots source;
    FileSlots destination;
};

struct NetworkSlots
{
    yyjson_mut_val* direction = nullptr;
    yyjson_mut_val* source_ip = nullptr;
    yyjson_mut_val* destination_ip = nullptr;
    yyjson_mut_val* source_port = nullptr;
    yyjson_mut_val* destination_port = nullptr;
    yyjson_mut_val* protocol = nullptr;
    yyjson_mut_val* ip_type = nullptr;
    char source_ip_text[INET6_ADDRSTRLEN] = {};
    char destination_ip_text[INET6_ADDRSTRLEN] = {};
};

struct SignalSlots
{
    ProcessSlots process;
    yyjson_mut_val* signal = nullptr;
};

struct PtraceSlots
{
    ProcessSlots process;
    yyjson_mut_val* mode = nullptr;
};

class MutableDoc
{
public:
    MutableDoc()
        : m_doc(yyjson_mut_doc_new(nullptr))
    {
        if (m_doc == nullptr)
        {
            throw std::bad_alloc();
        }
    }

    ~MutableDoc()
    {
        yyjson_mut_doc_free(m_doc);
    }

    MutableDoc(const MutableDoc&) = delete;
    MutableDoc& operator=(const MutableDoc&) = delete;

    yyjson_mut_doc* get() const
    {
        return m_doc;
    }

private:
    yyjson_mut_doc* m_doc;
};

class Tree
{
public:
    explicit Tree(yyjson_mut_doc* doc)
        : m_doc(doc)
    {
    }

    yyjson_mut_val* object()
    {
        yyjson_mut_val* value = yyjson_mut_obj(m_doc);
        if (value == nullptr)
        {
            throw std::bad_alloc();
        }
        return value;
    }

    yyjson_mut_val* key(const char* text)
    {
        yyjson_mut_val* name = yyjson_mut_str(m_doc, text);
        if (name == nullptr)
        {
            throw std::bad_alloc();
        }
        return name;
    }

    void add(yyjson_mut_val* parent, const char* key_text, yyjson_mut_val* child)
    {
        yyjson_mut_val* name = yyjson_mut_str(m_doc, key_text);
        if (name == nullptr || child == nullptr || !yyjson_mut_obj_add(parent, name, child))
        {
            throw std::bad_alloc();
        }
    }

    yyjson_mut_val* uintField(yyjson_mut_val* parent, const char* key_text)
    {
        yyjson_mut_val* value = yyjson_mut_uint(m_doc, 0);
        if (value == nullptr)
        {
            throw std::bad_alloc();
        }
        add(parent, key_text, value);
        return value;
    }

    yyjson_mut_val* sintField(yyjson_mut_val* parent, const char* key_text)
    {
        yyjson_mut_val* value = yyjson_mut_sint(m_doc, 0);
        if (value == nullptr)
        {
            throw std::bad_alloc();
        }
        add(parent, key_text, value);
        return value;
    }

    yyjson_mut_val* stringField(yyjson_mut_val* parent, const char* key_text)
    {
        yyjson_mut_val* value = yyjson_mut_strn(m_doc, "", 0);
        if (value == nullptr)
        {
            throw std::bad_alloc();
        }
        add(parent, key_text, value);
        return value;
    }

    FileSlots addFile(yyjson_mut_val* parent, const char* key_text)
    {
        yyjson_mut_val* obj = object();
        FileSlots slots;
        slots.inode = uintField(obj, "inode");
        slots.dev = uintField(obj, "dev");
        slots.path = stringField(obj, "path");
        yyjson_mut_val* owner = object();
        slots.owner_uid = uintField(owner, "uid");
        slots.owner_gid = uintField(owner, "gid");
        add(obj, "owner", owner);
        slots.mode = uintField(obj, "mode");
        slots.type = stringField(obj, "type");
        slots.suid = uintField(obj, "suid");
        slots.sgid = uintField(obj, "sgid");
        slots.last_modified_seconds = uintField(obj, "last_modified_seconds");
        slots.nlink = uintField(obj, "nlink");
        slots.filename = stringField(obj, "filename");
        add(parent, key_text, obj);
        return slots;
    }

    ProcessSlots addProcess(yyjson_mut_val* parent, const char* key_text)
    {
        yyjson_mut_val* obj = object();
        ProcessSlots slots;
        slots.pid = uintField(obj, "pid");
        slots.ns_pid = uintField(obj, "ns_pid");
        slots.ppid = uintField(obj, "ppid");
        slots.ns_ppid = uintField(obj, "ns_ppid");
        slots.ruid = uintField(obj, "ruid");
        slots.rgid = uintField(obj, "rgid");
        slots.euid = uintField(obj, "euid");
        slots.egid = uintField(obj, "egid");
        slots.suid = uintField(obj, "suid");
        slots.cgroup_id = uintField(obj, "cgroup_id");
        slots.start_time = uintField(obj, "start_time");
        slots.ptrace_flags = uintField(obj, "ptrace_flags");
        slots.file = addFile(obj, "file");
        slots.cmd = stringField(obj, "cmd");
        yyjson_mut_val* stdio = object();
        slots.stdin_fd = stringField(stdio, "stdin");
        slots.stdout_fd = stringField(stdio, "stdout");
        slots.stderr_fd = stringField(stdio, "stderr");
        add(obj, "stdio_file_descriptors_at_process_creation", stdio);
        slots.shell_command = stringField(obj, "shell_command");
        add(parent, key_text, obj);
        return slots;
    }

    CommonSlots addCommon(yyjson_mut_val* root)
    {
        CommonSlots slots;
        slots.id = uintField(root, "id");
        slots.type = stringField(root, "type");
        slots.action = stringField(root, "action");
        slots.matched_rule_id = uintField(root, "matched_rule_id");
        slots.had_error = uintField(root, "had_error");
        slots.process = addProcess(root, "process");
        slots.parent_process = addProcess(root, "parent_process");
        slots.time = uintField(root, "time");
        return slots;
    }

private:
    yyjson_mut_doc* m_doc;
};

class Attachment
{
public:
    Attachment(yyjson_mut_val* root, yyjson_mut_val* kubernetes_key, yyjson_mut_val* metadata_key)
        : m_root(root)
        , m_kubernetes_key(kubernetes_key)
        , m_metadata_key(metadata_key)
    {
    }

    ~Attachment()
    {
        detach(m_kubernetes_on, m_kubernetes_key);
        detach(m_metadata_on, m_metadata_key);
    }

    Attachment(const Attachment&) = delete;
    Attachment& operator=(const Attachment&) = delete;

    bool addKubernetes(yyjson_mut_val* value)
    {
        return add(m_kubernetes_key, value, m_kubernetes_on);
    }

    bool addMetadata(yyjson_mut_val* value)
    {
        return add(m_metadata_key, value, m_metadata_on);
    }

private:
    bool add(yyjson_mut_val* key, yyjson_mut_val* value, bool& attached)
    {
        if (!yyjson_mut_obj_add(m_root, key, value))
        {
            return false;
        }
        attached = true;
        return true;
    }

    void detach(bool& attached, yyjson_mut_val* key)
    {
        if (!attached)
        {
            return;
        }
        yyjson_mut_obj_remove(m_root, key);
        attached = false;
    }

    yyjson_mut_val* m_root;
    yyjson_mut_val* m_kubernetes_key;
    yyjson_mut_val* m_metadata_key;
    bool m_kubernetes_on = false;
    bool m_metadata_on = false;
};

class PoolDoc
{
public:
    explicit PoolDoc(yyjson_mut_doc* doc)
        : m_doc(doc)
    {
    }

    ~PoolDoc()
    {
        yyjson_mut_doc_free(m_doc);
    }

    PoolDoc(const PoolDoc&) = delete;
    PoolDoc& operator=(const PoolDoc&) = delete;

    yyjson_mut_doc* get() const
    {
        return m_doc;
    }

    yyjson_mut_doc* release()
    {
        yyjson_mut_doc* doc = m_doc;
        m_doc = nullptr;
        return doc;
    }

private:
    yyjson_mut_doc* m_doc;
};

class OptionalJsonBuilder
{
public:
    explicit OptionalJsonBuilder(yyjson_mut_doc* doc)
        : m_doc(doc)
    {
    }

    bool ok() const
    {
        return !m_memory_failed;
    }

    yyjson_mut_val* kubernetesObject(const Kubernetes& kubernetes)
    {
        yyjson_mut_val* obj = newObject();
        addStringIfNotEmpty(obj, "node_name", kubernetes.node_name);
        if (kubernetes.container_id != 0)
        {
            addUint(obj, "container_id", kubernetes.container_id);
        }
        addStringIfNotEmpty(obj, "pod_uid", kubernetes.pod_uid);
        addStringIfNotEmpty(obj, "pod_namespace", kubernetes.pod_namespace);
        addStringIfNotEmpty(obj, "pod_name", kubernetes.pod_name);
        if (!kubernetes.pod_labels.empty())
        {
            addValue(obj, "pod_labels", labelObject(kubernetes.pod_labels));
        }
        addBool(obj, "host_event", kubernetes.host_event);
        return obj;
    }

    yyjson_mut_val* metadataObject(const config::RuleMetadata& metadata)
    {
        yyjson_mut_val* obj = newObject();
        addStringIfNotEmpty(obj, "description", metadata.description);
        addStringIfNotEmpty(obj, "title", metadata.title);
        if (metadata.severity != RULE_SEVERITY_UNKNOWN)
        {
            addLiteral(obj, "severity", severityString(metadata.severity));
        }
        if (!metadata.mitre_tags.empty())
        {
            addValue(obj, "mitre_tags", stringArray(metadata.mitre_tags));
        }
        addStringIfNotEmpty(obj, "name", metadata.name);
        addStringIfNotEmpty(obj, "author", metadata.author);
        addStringIfNotEmpty(obj, "status", metadata.status);
        return obj;
    }

private:
    yyjson_mut_val* labelObject(const std::map<std::string, std::string>& labels)
    {
        yyjson_mut_val* obj = newObject();
        for (const auto& label : labels)
        {
            if (!ok())
            {
                return obj;
            }
            if (!yyjson_mut_obj_add_strn(m_doc, obj, label.first.c_str(), label.second.data(), label.second.size()))
            {
                m_memory_failed = true;
            }
        }
        return obj;
    }

    yyjson_mut_val* stringArray(const std::vector<std::string>& values)
    {
        yyjson_mut_val* arr = newArray();
        for (const std::string& value : values)
        {
            if (!ok())
            {
                return arr;
            }
            if (!yyjson_mut_arr_add_strn(m_doc, arr, value.data(), value.size()))
            {
                m_memory_failed = true;
            }
        }
        return arr;
    }

    static const char* severityString(rule_severity severity)
    {
        switch (severity)
        {
            case RULE_SEVERITY_UNKNOWN: return "unknown";
            case RULE_SEVERITY_INFORMATIONAL: return "informational";
            case RULE_SEVERITY_LOW: return "low";
            case RULE_SEVERITY_MEDIUM: return "medium";
            case RULE_SEVERITY_HIGH: return "high";
            case RULE_SEVERITY_CRITICAL: return "critical";
            default: return "unknown";
        }
    }

    yyjson_mut_val* newObject()
    {
        if (!ok())
        {
            return nullptr;
        }
        yyjson_mut_val* value = yyjson_mut_obj(m_doc);
        if (value == nullptr)
        {
            m_memory_failed = true;
        }
        return value;
    }

    yyjson_mut_val* newArray()
    {
        if (!ok())
        {
            return nullptr;
        }
        yyjson_mut_val* value = yyjson_mut_arr(m_doc);
        if (value == nullptr)
        {
            m_memory_failed = true;
        }
        return value;
    }

    void addValue(yyjson_mut_val* parent, const char* key, yyjson_mut_val* child)
    {
        if (!ok())
        {
            return;
        }
        if (child == nullptr || !yyjson_mut_obj_add_val(m_doc, parent, key, child))
        {
            m_memory_failed = true;
        }
    }

    void addUint(yyjson_mut_val* obj, const char* key, uint64_t value)
    {
        if (!ok())
        {
            return;
        }
        if (!yyjson_mut_obj_add_uint(m_doc, obj, key, value))
        {
            m_memory_failed = true;
        }
    }

    void addBool(yyjson_mut_val* obj, const char* key, bool value)
    {
        if (!ok())
        {
            return;
        }
        if (!yyjson_mut_obj_add_bool(m_doc, obj, key, value))
        {
            m_memory_failed = true;
        }
    }

    void addString(yyjson_mut_val* obj, const char* key, const std::string& value)
    {
        if (!ok())
        {
            return;
        }
        if (!yyjson_mut_obj_add_strn(m_doc, obj, key, value.data(), value.size()))
        {
            m_memory_failed = true;
        }
    }

    void addStringIfNotEmpty(yyjson_mut_val* obj, const char* key, const std::string& value)
    {
        if (value.empty())
        {
            return;
        }
        addString(obj, key, value);
    }

    void addLiteral(yyjson_mut_val* obj, const char* key, const char* value)
    {
        if (!ok())
        {
            return;
        }
        if (!yyjson_mut_obj_add_str(m_doc, obj, key, value))
        {
            m_memory_failed = true;
        }
    }

    yyjson_mut_doc* m_doc;
    bool m_memory_failed = false;
};

// One document per data shape, built once. An event overwrites the leaves and
// yyjson walks that same tree. String leaves point at the event until write
// returns. kubernetes and matched_rule_metadata change shape, so those objects
// are built in a scratch document and linked only for that write.
struct EventJsonWriter::Shapes
{
    template <typename DataSlots>
    struct EventShape
    {
        MutableDoc doc;
        yyjson_mut_val* root = nullptr;
        CommonSlots common;
        DataSlots data;
        yyjson_mut_val* kubernetes_key = nullptr;
        yyjson_mut_val* metadata_key = nullptr;
    };

    struct ErrorShape
    {
        MutableDoc doc;
        yyjson_mut_val* root = nullptr;
        yyjson_mut_val* error_code = nullptr;
        yyjson_mut_val* location = nullptr;
        yyjson_mut_val* details = nullptr;
    };

    Shapes();

    template <typename Emit>
    void writeEvent(const Event& event, Emit&& emit);

    template <typename Emit>
    void writeError(const Error& error, Emit&& emit);

private:
    template <typename DataSlots, typename Data, typename Emit>
    void writeShape(EventShape<DataSlots>& shape, const Event& event, const Data& data, Emit&& emit);

    template <typename DataSlots>
    void finish(EventShape<DataSlots>& shape, Tree& tree, yyjson_mut_val* root);

    bool fillCommon(const CommonSlots& slots, const Event& event) const;
    bool fillProcess(const ProcessSlots& slots, const Process& process) const;
    bool fillFile(const FileSlots& slots, const File& file) const;
    bool fillData(const ChownSlots& slots, const ChownEventData& data) const;
    bool fillData(const ChmodSlots& slots, const ChmodEventData& data) const;
    bool fillData(const ForkSlots& slots, const ForkEventData& data) const;
    bool fillData(const ExecSlots& slots, const ExecEventData& data) const;
    bool fillData(const ExitSlots& slots, const ExitEventData& data) const;
    bool fillData(const GenericFileSlots& slots, const GenericFileEventData& data) const;
    bool fillData(const RenameSlots& slots, const RenameEventData& data) const;
    bool fillData(NetworkSlots& slots, const NetworkEventData& data) const;
    bool fillData(const SignalSlots& slots, const SignalEventData& data) const;
    bool fillData(const PtraceSlots& slots, const PtraceEventData& data) const;

    template <typename Enum>
    bool setEnum(yyjson_mut_val* slot, Enum value) const;
    void setString(yyjson_mut_val* slot, std::string_view value) const;
    void setUint(yyjson_mut_val* slot, uint64_t value) const;
    void setSint(yyjson_mut_val* slot, int64_t value) const;
    void setAddress(char* buffer, yyjson_mut_val* slot, int family, const void* address) const;

    yyjson_mut_doc* tryBuildOptional(const Event& event, yyjson_mut_val*& kubernetes, yyjson_mut_val*& metadata);
    bool growPools();
    size_t poolBytes() const;
    static size_t bytesToSlots(size_t bytes);
    static void logFailure(const char* reason);

    void buildChown();
    void buildChmod();
    void buildFork();
    void buildExec();
    void buildExit();
    void buildGenericFile();
    void buildRename();
    void buildNetwork();
    void buildSignal();
    void buildPtrace();
    void buildError();

    static constexpr size_t INITIAL_POOL_BYTES = 64 * 1024;
    static constexpr size_t MAX_POOL_BYTES = 8 * 1024 * 1024;
    static constexpr size_t INITIAL_VALUE_SLOTS = 1024;
    static constexpr int MAX_BUILD_ATTEMPTS = 5;

    EventShape<ChownSlots> m_chown;
    EventShape<ChmodSlots> m_chmod;
    EventShape<ForkSlots> m_fork;
    EventShape<ExecSlots> m_exec;
    EventShape<ExitSlots> m_exit;
    EventShape<GenericFileSlots> m_generic_file;
    EventShape<RenameSlots> m_rename;
    EventShape<NetworkSlots> m_network;
    EventShape<SignalSlots> m_signal;
    EventShape<PtraceSlots> m_ptrace;
    ErrorShape m_error;
    std::vector<std::max_align_t> m_pool;
    size_t m_value_slots = INITIAL_VALUE_SLOTS;
};

EventJsonWriter::Shapes::Shapes()
{
    static_assert(std::variant_size_v<EventData> == 10);
    static_assert(std::is_same_v<std::variant_alternative_t<0, EventData>, ChownEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<1, EventData>, ChmodEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<2, EventData>, ForkEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<3, EventData>, ExecEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<4, EventData>, ExitEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<5, EventData>, GenericFileEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<6, EventData>, RenameEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<7, EventData>, NetworkEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<8, EventData>, SignalEventData>);
    static_assert(std::is_same_v<std::variant_alternative_t<9, EventData>, PtraceEventData>);

    m_pool.resize(bytesToSlots(INITIAL_POOL_BYTES));
    buildChown();
    buildChmod();
    buildFork();
    buildExec();
    buildExit();
    buildGenericFile();
    buildRename();
    buildNetwork();
    buildSignal();
    buildPtrace();
    buildError();
}

template <typename DataSlots>
void EventJsonWriter::Shapes::finish(EventShape<DataSlots>& shape, Tree& tree, yyjson_mut_val* root)
{
    shape.root = root;
    shape.kubernetes_key = tree.key("kubernetes");
    shape.metadata_key = tree.key("matched_rule_metadata");
    yyjson_mut_doc_set_root(shape.doc.get(), root);
}

void EventJsonWriter::Shapes::buildChown()
{
    Tree tree(m_chown.doc.get());
    yyjson_mut_val* root = tree.object();
    m_chown.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    yyjson_mut_val* target = tree.object();
    m_chown.data.file = tree.addFile(target, "file");
    tree.add(data, "target", target);
    yyjson_mut_val* chown = tree.object();
    m_chown.data.uid = tree.uintField(chown, "requested_owner_uid");
    m_chown.data.gid = tree.uintField(chown, "requested_owner_gid");
    tree.add(data, "chown", chown);
    tree.add(root, "data", data);
    finish(m_chown, tree, root);
}

void EventJsonWriter::Shapes::buildChmod()
{
    Tree tree(m_chmod.doc.get());
    yyjson_mut_val* root = tree.object();
    m_chmod.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    yyjson_mut_val* target = tree.object();
    m_chmod.data.file = tree.addFile(target, "file");
    tree.add(data, "target", target);
    yyjson_mut_val* chmod = tree.object();
    m_chmod.data.mode = tree.uintField(chmod, "requested_mode");
    tree.add(data, "chmod", chmod);
    tree.add(root, "data", data);
    finish(m_chmod, tree, root);
}

void EventJsonWriter::Shapes::buildFork()
{
    Tree tree(m_fork.doc.get());
    yyjson_mut_val* root = tree.object();
    m_fork.common = tree.addCommon(root);
    tree.add(root, "data", tree.object());
    finish(m_fork, tree, root);
}

void EventJsonWriter::Shapes::buildExec()
{
    Tree tree(m_exec.doc.get());
    yyjson_mut_val* root = tree.object();
    m_exec.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    yyjson_mut_val* target = tree.object();
    m_exec.data.process = tree.addProcess(target, "process");
    tree.add(data, "target", target);
    tree.add(root, "data", data);
    finish(m_exec, tree, root);
}

void EventJsonWriter::Shapes::buildExit()
{
    Tree tree(m_exit.doc.get());
    yyjson_mut_val* root = tree.object();
    m_exit.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    m_exit.data.exit_code = tree.uintField(data, "exit_code");
    m_exit.data.signal = tree.uintField(data, "signal");
    tree.add(root, "data", data);
    finish(m_exit, tree, root);
}

void EventJsonWriter::Shapes::buildGenericFile()
{
    Tree tree(m_generic_file.doc.get());
    yyjson_mut_val* root = tree.object();
    m_generic_file.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    yyjson_mut_val* target = tree.object();
    m_generic_file.data.file = tree.addFile(target, "file");
    tree.add(data, "target", target);
    tree.add(root, "data", data);
    finish(m_generic_file, tree, root);
}

void EventJsonWriter::Shapes::buildRename()
{
    Tree tree(m_rename.doc.get());
    yyjson_mut_val* root = tree.object();
    m_rename.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    m_rename.data.flags = tree.uintField(data, "flags");
    yyjson_mut_val* rename = tree.object();
    m_rename.data.source = tree.addFile(rename, "source_file");
    m_rename.data.destination = tree.addFile(rename, "destination_file");
    tree.add(data, "rename", rename);
    tree.add(root, "data", data);
    finish(m_rename, tree, root);
}

void EventJsonWriter::Shapes::buildNetwork()
{
    Tree tree(m_network.doc.get());
    yyjson_mut_val* root = tree.object();
    m_network.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    yyjson_mut_val* network = tree.object();
    m_network.data.direction = tree.stringField(network, "direction");
    m_network.data.source_ip = tree.stringField(network, "source_ip");
    m_network.data.destination_ip = tree.stringField(network, "destination_ip");
    m_network.data.source_port = tree.uintField(network, "source_port");
    m_network.data.destination_port = tree.uintField(network, "destination_port");
    m_network.data.protocol = tree.uintField(network, "protocol");
    m_network.data.ip_type = tree.uintField(network, "ip_type");
    tree.add(data, "network", network);
    tree.add(root, "data", data);
    finish(m_network, tree, root);
}

void EventJsonWriter::Shapes::buildSignal()
{
    Tree tree(m_signal.doc.get());
    yyjson_mut_val* root = tree.object();
    m_signal.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    yyjson_mut_val* target = tree.object();
    m_signal.data.process = tree.addProcess(target, "process");
    tree.add(data, "target", target);
    m_signal.data.signal = tree.uintField(data, "signal");
    tree.add(root, "data", data);
    finish(m_signal, tree, root);
}

void EventJsonWriter::Shapes::buildPtrace()
{
    Tree tree(m_ptrace.doc.get());
    yyjson_mut_val* root = tree.object();
    m_ptrace.common = tree.addCommon(root);
    yyjson_mut_val* data = tree.object();
    yyjson_mut_val* target = tree.object();
    m_ptrace.data.process = tree.addProcess(target, "process");
    tree.add(data, "target", target);
    m_ptrace.data.mode = tree.uintField(data, "mode");
    tree.add(root, "data", data);
    finish(m_ptrace, tree, root);
}

void EventJsonWriter::Shapes::buildError()
{
    Tree tree(m_error.doc.get());
    yyjson_mut_val* root = tree.object();
    m_error.root = root;
    m_error.error_code = tree.sintField(root, "error_code");
    m_error.location = tree.stringField(root, "location");
    m_error.details = tree.stringField(root, "details");
    yyjson_mut_doc_set_root(m_error.doc.get(), root);
}

template <typename Emit>
void EventJsonWriter::Shapes::writeEvent(const Event& event, Emit&& emit)
{
    switch (event.data.index())
    {
        case 0:
            writeShape(m_chown, event, std::get<ChownEventData>(event.data), emit);
            return;
        case 1:
            writeShape(m_chmod, event, std::get<ChmodEventData>(event.data), emit);
            return;
        case 2:
            writeShape(m_fork, event, std::get<ForkEventData>(event.data), emit);
            return;
        case 3:
            writeShape(m_exec, event, std::get<ExecEventData>(event.data), emit);
            return;
        case 4:
            writeShape(m_exit, event, std::get<ExitEventData>(event.data), emit);
            return;
        case 5:
            writeShape(m_generic_file, event, std::get<GenericFileEventData>(event.data), emit);
            return;
        case 6:
            writeShape(m_rename, event, std::get<RenameEventData>(event.data), emit);
            return;
        case 7:
            writeShape(m_network, event, std::get<NetworkEventData>(event.data), emit);
            return;
        case 8:
            writeShape(m_signal, event, std::get<SignalEventData>(event.data), emit);
            return;
        case 9:
            writeShape(m_ptrace, event, std::get<PtraceEventData>(event.data), emit);
            return;
        default:
            logFailure("invalid value");
            return;
    }
}

template <typename Emit>
void EventJsonWriter::Shapes::writeError(const Error& error, Emit&& emit)
{
    setSint(m_error.error_code, error.error_code);
    setString(m_error.location, error.location);
    setString(m_error.details, error.details);
    emit(m_error.doc.get());
}

template <typename DataSlots, typename Data, typename Emit>
void EventJsonWriter::Shapes::writeShape(EventShape<DataSlots>& shape, const Event& event, const Data& data, Emit&& emit)
{
    if (!fillCommon(shape.common, event) || !fillData(shape.data, data))
    {
        logFailure("invalid value");
        return;
    }

    const bool want_kubernetes = event.kubernetes.hasAnyValue();
    const bool want_metadata = event.matched_rule_metadata.hasAnyValue();
    if (!want_kubernetes && !want_metadata)
    {
        emit(shape.doc.get());
        return;
    }

    yyjson_mut_val* kubernetes = nullptr;
    yyjson_mut_val* metadata = nullptr;
    yyjson_mut_doc* optional_doc = tryBuildOptional(event, kubernetes, metadata);
    if (optional_doc == nullptr)
    {
        logFailure("not enough memory");
        return;
    }

    PoolDoc pool_doc(optional_doc);
    Attachment attachment(shape.root, shape.kubernetes_key, shape.metadata_key);
    if (kubernetes != nullptr && !attachment.addKubernetes(kubernetes))
    {
        logFailure("not enough memory");
        return;
    }
    if (metadata != nullptr && !attachment.addMetadata(metadata))
    {
        logFailure("not enough memory");
        return;
    }
    emit(shape.doc.get());
}

template <typename Enum>
bool EventJsonWriter::Shapes::setEnum(yyjson_mut_val* slot, Enum value) const
{
    std::string_view name = magic_enum::enum_name(value);
    if (name.empty())
    {
        if constexpr (std::is_same_v<Enum, file_type>)
        {
            name = "UNKNOWN_FILE_TYPE";
        }
        else
        {
            return false;
        }
    }
    return yyjson_mut_set_strn(slot, name.data(), name.size());
}

void EventJsonWriter::Shapes::setString(yyjson_mut_val* slot, std::string_view value) const
{
    yyjson_mut_set_strn(slot, value.data(), value.size());
}

void EventJsonWriter::Shapes::setUint(yyjson_mut_val* slot, uint64_t value) const
{
    yyjson_mut_set_uint(slot, value);
}

void EventJsonWriter::Shapes::setSint(yyjson_mut_val* slot, int64_t value) const
{
    yyjson_mut_set_sint(slot, value);
}

void EventJsonWriter::Shapes::setAddress(char* buffer, yyjson_mut_val* slot, int family, const void* address) const
{
    buffer[0] = '\0';
    inet_ntop(family, address, buffer, INET6_ADDRSTRLEN);
    yyjson_mut_set_strn(slot, buffer, std::strlen(buffer));
}

bool EventJsonWriter::Shapes::fillCommon(const CommonSlots& slots, const Event& event) const
{
    setUint(slots.id, event.id);
    if (!setEnum(slots.type, event.type) || !setEnum(slots.action, event.action))
    {
        return false;
    }
    setUint(slots.matched_rule_id, event.matched_rule_id);
    setUint(slots.had_error, event.had_error_while_handling);
    if (!fillProcess(slots.process, event.process) || !fillProcess(slots.parent_process, event.parent_process))
    {
        return false;
    }
    setUint(slots.time, event.time);
    return true;
}

bool EventJsonWriter::Shapes::fillProcess(const ProcessSlots& slots, const Process& process) const
{
    setUint(slots.pid, process.pid);
    setUint(slots.ns_pid, process.ns_pid);
    setUint(slots.ppid, process.ppid);
    setUint(slots.ns_ppid, process.ns_ppid);
    setUint(slots.ruid, process.ruid);
    setUint(slots.rgid, process.rgid);
    setUint(slots.euid, process.euid);
    setUint(slots.egid, process.egid);
    setUint(slots.suid, process.suid);
    setUint(slots.cgroup_id, process.cgroup_id);
    setUint(slots.start_time, process.start_time);
    setUint(slots.ptrace_flags, process.ptrace_flags);
    if (!fillFile(slots.file, process.file))
    {
        return false;
    }
    setString(slots.cmd, process.cmd.value);
    const auto& stdio = process.stdio_file_descriptors_at_process_creation;
    if (!setEnum(slots.stdin_fd, stdio.stdin_fd) || !setEnum(slots.stdout_fd, stdio.stdout_fd) || !setEnum(slots.stderr_fd, stdio.stderr_fd))
    {
        return false;
    }
    setString(slots.shell_command, process.shell_command.value);
    return true;
}

bool EventJsonWriter::Shapes::fillFile(const FileSlots& slots, const File& file) const
{
    setUint(slots.inode, file.inode);
    setUint(slots.dev, file.dev);
    setString(slots.path, file.path.value);
    setUint(slots.owner_uid, file.owner.uid);
    setUint(slots.owner_gid, file.owner.gid);
    setUint(slots.mode, file.mode);
    if (!setEnum(slots.type, file.type))
    {
        return false;
    }
    setUint(slots.suid, file.suid);
    setUint(slots.sgid, file.sgid);
    setUint(slots.last_modified_seconds, file.last_modified_seconds);
    setUint(slots.nlink, file.nlink);
    setString(slots.filename, file.filename.value);
    return true;
}

bool EventJsonWriter::Shapes::fillData(const ChownSlots& slots, const ChownEventData& data) const
{
    if (!fillFile(slots.file, data.file))
    {
        return false;
    }
    setUint(slots.uid, data.requested_owner_uid);
    setUint(slots.gid, data.requested_owner_gid);
    return true;
}

bool EventJsonWriter::Shapes::fillData(const ChmodSlots& slots, const ChmodEventData& data) const
{
    if (!fillFile(slots.file, data.file))
    {
        return false;
    }
    setUint(slots.mode, data.requested_mode);
    return true;
}

bool EventJsonWriter::Shapes::fillData(const ForkSlots&, const ForkEventData&) const
{
    return true;
}

bool EventJsonWriter::Shapes::fillData(const ExecSlots& slots, const ExecEventData& data) const
{
    return fillProcess(slots.process, data.new_process);
}

bool EventJsonWriter::Shapes::fillData(const ExitSlots& slots, const ExitEventData& data) const
{
    setUint(slots.exit_code, data.exit_code);
    setUint(slots.signal, data.signal);
    return true;
}

bool EventJsonWriter::Shapes::fillData(const GenericFileSlots& slots, const GenericFileEventData& data) const
{
    return fillFile(slots.file, data.file);
}

bool EventJsonWriter::Shapes::fillData(const RenameSlots& slots, const RenameEventData& data) const
{
    setUint(slots.flags, data.flags);
    return fillFile(slots.source, data.source_file) && fillFile(slots.destination, data.destination_file);
}

bool EventJsonWriter::Shapes::fillData(NetworkSlots& slots, const NetworkEventData& data) const
{
    if (!setEnum(slots.direction, data.direction))
    {
        return false;
    }
    if (data.ip_type == AF_INET)
    {
        const auto& addresses = std::get<Ipv4Addresses>(data.addresses);
        in_addr source{};
        in_addr destination{};
        source.s_addr = addresses.source_ip;
        destination.s_addr = addresses.destination_ip;
        setAddress(slots.source_ip_text, slots.source_ip, AF_INET, &source);
        setAddress(slots.destination_ip_text, slots.destination_ip, AF_INET, &destination);
    }
    else
    {
        const auto& addresses = std::get<Ipv6Addresses>(data.addresses);
        in6_addr source{};
        in6_addr destination{};
        std::memcpy(source.s6_addr, addresses.source_ip, sizeof(source.s6_addr));
        std::memcpy(destination.s6_addr, addresses.destination_ip, sizeof(destination.s6_addr));
        setAddress(slots.source_ip_text, slots.source_ip, AF_INET6, &source);
        setAddress(slots.destination_ip_text, slots.destination_ip, AF_INET6, &destination);
    }
    setUint(slots.source_port, data.source_port);
    setUint(slots.destination_port, data.destination_port);
    setUint(slots.protocol, data.protocol);
    setUint(slots.ip_type, data.ip_type);
    return true;
}

bool EventJsonWriter::Shapes::fillData(const SignalSlots& slots, const SignalEventData& data) const
{
    if (!fillProcess(slots.process, data.process))
    {
        return false;
    }
    setUint(slots.signal, data.signal);
    return true;
}

bool EventJsonWriter::Shapes::fillData(const PtraceSlots& slots, const PtraceEventData& data) const
{
    if (!fillProcess(slots.process, data.process))
    {
        return false;
    }
    setUint(slots.mode, data.mode);
    return true;
}

yyjson_mut_doc* EventJsonWriter::Shapes::tryBuildOptional(
    const Event& event,
    yyjson_mut_val*& kubernetes,
    yyjson_mut_val*& metadata)
{
    kubernetes = nullptr;
    metadata = nullptr;
    for (int attempt = 0; attempt < MAX_BUILD_ATTEMPTS; ++attempt)
    {
        yyjson_alc allocator{};
        if (!yyjson_alc_pool_init(&allocator, m_pool.data(), poolBytes()))
        {
            if (!growPools())
            {
                return nullptr;
            }
            continue;
        }

        yyjson_mut_doc* doc = yyjson_mut_doc_new(&allocator);
        if (doc == nullptr || !yyjson_mut_doc_set_val_pool_size(doc, m_value_slots))
        {
            yyjson_mut_doc_free(doc);
            if (!growPools())
            {
                return nullptr;
            }
            continue;
        }

        OptionalJsonBuilder builder(doc);
        if (event.kubernetes.hasAnyValue())
        {
            kubernetes = builder.kubernetesObject(event.kubernetes);
        }
        if (event.matched_rule_metadata.hasAnyValue())
        {
            metadata = builder.metadataObject(event.matched_rule_metadata);
        }
        if (builder.ok() && (kubernetes != nullptr || metadata != nullptr))
        {
            return doc;
        }

        yyjson_mut_doc_free(doc);
        kubernetes = nullptr;
        metadata = nullptr;
        if (builder.ok() || !growPools())
        {
            return nullptr;
        }
    }
    return nullptr;
}

bool EventJsonWriter::Shapes::growPools()
{
    const size_t bytes = poolBytes();
    if (bytes >= MAX_POOL_BYTES)
    {
        return false;
    }
    m_value_slots *= 2;
    m_pool.resize(bytesToSlots(bytes * 2));
    return true;
}

size_t EventJsonWriter::Shapes::poolBytes() const
{
    return m_pool.size() * sizeof(std::max_align_t);
}

size_t EventJsonWriter::Shapes::bytesToSlots(size_t bytes)
{
    return (bytes + sizeof(std::max_align_t) - 1) / sizeof(std::max_align_t);
}

void EventJsonWriter::Shapes::logFailure(const char* reason)
{
    LOG_ERROR("Failed to serialize message to JSON: " << reason);
}

EventJsonWriter::EventJsonWriter()
    : m_shapes(std::make_unique<Shapes>())
{
    m_line.resize(INITIAL_LINE_BYTES);
}

EventJsonWriter::~EventJsonWriter() = default;

void EventJsonWriter::appendEvent(std::string& out, const Event& event)
{
    try
    {
        m_shapes->writeEvent(event, [&](yyjson_mut_doc* doc) {
            return writeLine(out, doc);
        });
    }
    catch (const std::exception& exception)
    {
        LOG_ERROR("Failed to serialize message to JSON: " << exception.what());
    }
}

void EventJsonWriter::appendError(std::string& out, const Error& error)
{
    try
    {
        m_shapes->writeError(error, [&](yyjson_mut_doc* doc) {
            return writeLine(out, doc);
        });
    }
    catch (const std::exception& exception)
    {
        LOG_ERROR("Failed to serialize message to JSON: " << exception.what());
    }
}

bool EventJsonWriter::writeLine(std::string& out, yyjson_mut_doc* doc)
{
    const yyjson_write_flag flags = YYJSON_WRITE_NEWLINE_AT_END;
    for (int attempt = 0; attempt < MAX_WRITE_ATTEMPTS; ++attempt)
    {
        yyjson_write_err error{};
        const size_t length = yyjson_mut_write_buf(m_line.data(), m_line.size(), doc, flags, &error);
        if (length > 0)
        {
            out.append(m_line.data(), length);
            return true;
        }
        if (error.code == YYJSON_WRITE_ERROR_MEMORY_ALLOCATION && m_line.size() < MAX_LINE_BYTES)
        {
            m_line.resize(m_line.size() * 2);
            continue;
        }
        const char* message = error.msg != nullptr ? error.msg : "write failed";
        LOG_ERROR("Failed to serialize message to JSON: " << message);
        return false;
    }

    LOG_ERROR("Failed to serialize message to JSON: output line too large");
    return false;
}

}
