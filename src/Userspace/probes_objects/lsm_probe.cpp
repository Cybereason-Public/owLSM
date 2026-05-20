#include "log_levels_enum.h"
#include "rodata_maps_related_structs.h"
#include "all_bpf.skel.h"

#include "lsm_probe.hpp"

namespace owlsm
{
    void LsmProbe::bpfOpen()
    {
        switch (m_event_type)
        {
            case CHMOD:         bpf_program__set_autoattach(m_skel->progs.chmod_hook_2, false);       break;
            case CHOWN:         bpf_program__set_autoattach(m_skel->progs.chown_hook_2, false);       break;
            case EXEC:          bpf_program__set_autoattach(m_skel->progs.exec_hook_2, false);        break;
            case FILE_CREATE:   bpf_program__set_autoattach(m_skel->progs.fc_hook_2, false);          break;
            case WRITE:         bpf_program__set_autoattach(m_skel->progs.write_hook_2, false);       break;
            case READ:          bpf_program__set_autoattach(m_skel->progs.read_hook_2, false);        break;
            case UNLINK:        bpf_program__set_autoattach(m_skel->progs.unlink_hook_2, false);      break;
            case RENAME:        bpf_program__set_autoattach(m_skel->progs.rename_hook_2, false);      break;
            case MKDIR:         bpf_program__set_autoattach(m_skel->progs.mkdir_hook_2, false);      break;
            case RMDIR:         bpf_program__set_autoattach(m_skel->progs.rmdir_hook_2, false);      break;
            case NETWORK:
            {
                bpf_program__set_autoattach(m_skel->progs.connect_hook_2, false);
                bpf_program__set_autoattach(m_skel->progs.accept_hook_2, false);
                bpf_program__set_autoattach(m_skel->progs.inet_conn_request_hook_2, false);
                break;
            }
            case SIGNAL: break;
            case PTRACE: break;
            default: break;
        }
    }

    void LsmProbe::bpfLoad()
    {
        switch (m_event_type)
        {
            case CHMOD:         addProgramToArray(m_skel->progs.chmod_hook_2, m_skel->maps.chmod_prog_array);   break;
            case CHOWN:         addProgramToArray(m_skel->progs.chown_hook_2, m_skel->maps.chown_prog_array);   break;
            case EXEC:          addProgramToArray(m_skel->progs.exec_hook_2, m_skel->maps.exec_prog_array);     break;
            case FILE_CREATE:   addProgramToArray(m_skel->progs.fc_hook_2, m_skel->maps.fc_prog_array);         break;
            case WRITE:         addProgramToArray(m_skel->progs.write_hook_2, m_skel->maps.write_prog_array);   break;
            case READ:          addProgramToArray(m_skel->progs.read_hook_2, m_skel->maps.read_prog_array);     break;
            case UNLINK:        addProgramToArray(m_skel->progs.unlink_hook_2, m_skel->maps.unlink_prog_array); break;
            case RENAME:        addProgramToArray(m_skel->progs.rename_hook_2, m_skel->maps.rename_prog_array); break;
            case MKDIR:         addProgramToArray(m_skel->progs.mkdir_hook_2, m_skel->maps.mkdir_prog_array); break;
            case RMDIR:         addProgramToArray(m_skel->progs.rmdir_hook_2, m_skel->maps.rmdir_prog_array); break;
            case NETWORK:
            {
                addProgramToArray(m_skel->progs.connect_hook_2, m_skel->maps.connect_prog_array);
                addProgramToArray(m_skel->progs.accept_hook_2, m_skel->maps.accept_prog_array);
                addProgramToArray(m_skel->progs.inet_conn_request_hook_2, m_skel->maps.inet_conn_request_prog_array);
                break;
            }
            case SIGNAL: break;
            case PTRACE: break;
            default: break;
        }
    }

    void LsmProbe::bpfAttach()
    {
        switch (m_event_type)
        {
            case CHMOD:       attachProbe(m_skel->progs.chmod_hook, &m_skel->links.chmod_hook);   break;
            case CHOWN:       attachProbe(m_skel->progs.chown_hook, &m_skel->links.chown_hook);   break;
            case FILE_CREATE: attachProbe(m_skel->progs.fc_hook, &m_skel->links.fc_hook);         break;
            case WRITE:       attachProbe(m_skel->progs.write_hook, &m_skel->links.write_hook);   break;
            case READ:        attachProbe(m_skel->progs.read_hook, &m_skel->links.read_hook);     break;
            case UNLINK:      attachProbe(m_skel->progs.unlink_hook, &m_skel->links.unlink_hook); break;
            case RENAME:      attachProbe(m_skel->progs.rename_hook, &m_skel->links.rename_hook); break;
            case MKDIR:       attachProbe(m_skel->progs.mkdir_hook, &m_skel->links.mkdir_hook); break;
            case RMDIR:       attachProbe(m_skel->progs.rmdir_hook, &m_skel->links.rmdir_hook); break;
            case EXEC:
            {
                attachProbe(m_skel->progs.bprm_creds_for_exec,&m_skel->links.bprm_creds_for_exec);
                attachProbe(m_skel->progs.bprm_committed_creds,&m_skel->links.bprm_committed_creds);
                attachProbe(m_skel->progs.exec_hook,&m_skel->links.exec_hook);
                break;
            }
            case NETWORK:
            {
                attachProbe(m_skel->progs.connect_hook, &m_skel->links.connect_hook);
                attachProbe(m_skel->progs.accept_hook, &m_skel->links.accept_hook);
                attachProbe(m_skel->progs.inet_conn_request_hook, &m_skel->links.inet_conn_request_hook);
                attachProbe(m_skel->progs.inet_conn_established, &m_skel->links.inet_conn_established);
                break;
            }
            case SIGNAL: attachProbe(m_skel->progs.signal_hook, &m_skel->links.signal_hook); break;
            case PTRACE: attachProbe(m_skel->progs.ptrace_hook, &m_skel->links.ptrace_hook); break;
            default: break;
        }
    }
}