#include "flatbuffer_to_json.hpp"

namespace
{

using json = nlohmann::json;

const char* fileTypeName(owlsm::fb::FileType t)
{
    const char* s = owlsm::fb::EnumNameFileType(t);
    return (s && *s) ? s : "UNKNOWN_FILE_TYPE";
}

json emptyFileObject()
{
    return json{
        {"inode", 0},
        {"dev", 0},
        {"path", ""},
        {"owner", json{{"uid", 0}, {"gid", 0}}},
        {"mode", 0},
        {"type", "UNKNOWN_FILE_TYPE"},
        {"suid", 0},
        {"sgid", 0},
        {"last_modified_seconds", 0},
        {"nlink", 0},
        {"filename", ""},
    };
}

json stdioDescriptorsJson(const owlsm::fb::StdioFileDescriptors* stdio)
{
    if (!stdio)
    {
        return json{
            {"stdin", "UNKNOWN_FILE_TYPE"},
            {"stdout", "UNKNOWN_FILE_TYPE"},
            {"stderr", "UNKNOWN_FILE_TYPE"},
        };
    }
    return json{
        {"stdin", fileTypeName(stdio->stdin())},
        {"stdout", fileTypeName(stdio->stdout())},
        {"stderr", fileTypeName(stdio->stderr())},
    };
}

const char* connectionDirectionName(owlsm::fb::ConnectionDirection d)
{
    const char* s = owlsm::fb::EnumNameConnectionDirection(d);
    return (s && *s) ? s : "INCOMING";
}

} // namespace

std::string FlatbufferToJson::fbStr(const flatbuffers::String* s)
{
    if (!s)
    {
        return "";
    }
    return s->str();
}

FlatbufferToJson::json FlatbufferToJson::ownerJson(const owlsm::fb::Owner* o)
{
    if (!o)
    {
        return json{{"uid", 0}, {"gid", 0}};
    }
    return json{{"uid", o->uid()}, {"gid", o->gid()}};
}

FlatbufferToJson::json FlatbufferToJson::fileJson(const owlsm::fb::File* f)
{
    if (!f)
    {
        return emptyFileObject();
    }
    return json{
        {"inode", f->inode()},
        {"dev", f->dev()},
        {"path", fbStr(f->path())},
        {"owner", ownerJson(f->owner())},
        {"mode", f->mode()},
        {"type", fileTypeName(f->type())},
        {"suid", f->suid()},
        {"sgid", f->sgid()},
        {"last_modified_seconds", f->last_modified_seconds()},
        {"nlink", f->nlink()},
        {"filename", fbStr(f->filename())},
    };
}

FlatbufferToJson::json FlatbufferToJson::processJson(const owlsm::fb::Process* p)
{
    if (!p)
    {
        return json{
            {"pid", 0},
            {"ppid", 0},
            {"ruid", 0},
            {"rgid", 0},
            {"euid", 0},
            {"egid", 0},
            {"suid", 0},
            {"cgroup_id", 0},
            {"start_time", 0},
            {"ptrace_flags", 0},
            {"file", emptyFileObject()},
            {"cmd", ""},
            {"stdio_file_descriptors_at_process_creation", stdioDescriptorsJson(nullptr)},
            {"shell_command", ""},
        };
    }
    return json{
        {"pid", p->pid()},
        {"ppid", p->ppid()},
        {"ruid", p->ruid()},
        {"rgid", p->rgid()},
        {"euid", p->euid()},
        {"egid", p->egid()},
        {"suid", p->suid()},
        {"cgroup_id", p->cgroup_id()},
        {"start_time", p->start_time()},
        {"ptrace_flags", p->ptrace_flags()},
        {"file", fileJson(p->file())},
        {"cmd", fbStr(p->cmd())},
        {"stdio_file_descriptors_at_process_creation", stdioDescriptorsJson(p->stdio_file_descriptors_at_process_creation())},
        {"shell_command", fbStr(p->shell_command())},
    };
}

FlatbufferToJson::json FlatbufferToJson::eventDataJson(const owlsm::fb::Event* ev)
{
    if (const auto* g = ev->data_as_GenericFileEventData())
    {
        const auto* t = g->target();
        return json{{"target", json{{"file", fileJson(t ? t->file() : nullptr)}}}};
    }
    if (const auto* c = ev->data_as_ChownEventData())
    {
        const auto* t = c->target();
        const auto* ch = c->chown();
        return json{
            {"target", json{{"file", fileJson(t ? t->file() : nullptr)}}},
            {"chown", json{
                {"requested_owner_uid", ch ? ch->requested_owner_uid() : 0u},
                {"requested_owner_gid", ch ? ch->requested_owner_gid() : 0u},
            }},
        };
    }
    if (const auto* m = ev->data_as_ChmodEventData())
    {
        const auto* t = m->target();
        const auto* ch = m->chmod();
        return json{
            {"target", json{{"file", fileJson(t ? t->file() : nullptr)}}},
            {"chmod", json{{"requested_mode", ch ? ch->requested_mode() : 0}}},
        };
    }
    if (const auto* x = ev->data_as_ExecEventData())
    {
        const auto* t = x->target();
        return json{{"target", json{{"process", processJson(t ? t->process() : nullptr)}}}};
    }
    if (ev->data_as_ForkEventData())
    {
        return json::object();
    }
    if (const auto* e = ev->data_as_ExitEventData())
    {
        return json{
            {"exit_code", e->exit_code()},
            {"signal", e->signal()},
        };
    }
    if (const auto* r = ev->data_as_RenameEventData())
    {
        const auto* ri = r->rename();
        return json{
            {"flags", r->flags()},
            {"rename", json{
                {"source_file", fileJson(ri ? ri->source_file() : nullptr)},
                {"destination_file", fileJson(ri ? ri->destination_file() : nullptr)},
            }},
        };
    }
    if (const auto* n = ev->data_as_NetworkEventData())
    {
        const auto* ni = n->network();
        if (!ni)
        {
            return json{
                {"network", json{
                    {"direction", "INCOMING"},
                    {"source_ip", ""},
                    {"destination_ip", ""},
                    {"source_port", 0},
                    {"destination_port", 0},
                    {"protocol", 0},
                    {"ip_type", 0},
                }},
            };
        }
        return json{
            {"network", json{
                {"direction", connectionDirectionName(ni->direction())},
                {"source_ip", fbStr(ni->source_ip())},
                {"destination_ip", fbStr(ni->destination_ip())},
                {"source_port", ni->source_port()},
                {"destination_port", ni->destination_port()},
                {"protocol", ni->protocol()},
                {"ip_type", ni->ip_type()},
            }},
        };
    }
    return json::object();
}

std::string FlatbufferToJson::jsonLineFromFlatbufferEvent(const owlsm::fb::Event* ev)
{
    json meta = json{{"description", ""}};
    if (const auto* m = ev->matched_rule_metadata())
    {
        meta = json{{"description", fbStr(m->description())}};
    }
    json j = json{
        {"id", ev->id()},
        {"type", owlsm::fb::EnumNameEventType(ev->type())},
        {"action", owlsm::fb::EnumNameAction(ev->action())},
        {"matched_rule_id", ev->matched_rule_id()},
        {"matched_rule_metadata", meta},
        {"had_error", static_cast<int>(ev->had_error())},
        {"process", processJson(ev->process())},
        {"parent_process", processJson(ev->parent_process())},
        {"time", ev->time()},
        {"data", eventDataJson(ev)},
    };
    return j.dump();
}

std::string FlatbufferToJson::jsonLineFromFlatbufferError(const owlsm::fb::Error* err)
{
    json j = json{
        {"error_code", err->error_code()},
        {"location", fbStr(err->location())},
        {"details", fbStr(err->details())},
    };
    return j.dump();
}
