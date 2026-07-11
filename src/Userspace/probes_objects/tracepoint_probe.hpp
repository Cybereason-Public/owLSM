#pragma once

#include "abstract_probe.hpp"
#include "globals/global_objects.hpp"

namespace owlsm
{
class TracepointProbe : public AbstractProbe
{
public:
    TracepointProbe() 
        : AbstractProbe(probe_type::TRACEPOINT) {}

    virtual ~TracepointProbe() override = default;

    virtual void bpfAttach() override
    {
        attachProbe(m_skel->progs.syscall_enter,&m_skel->links.syscall_enter);
        if (!globals::g_config.features.legacy_exec)
        {
            attachProbe(m_skel->progs.handle_sys_enter_execve,&m_skel->links.handle_sys_enter_execve);
            attachProbe(m_skel->progs.handle_sys_enter_execveat,&m_skel->links.handle_sys_enter_execveat);
        }
    }

};
}