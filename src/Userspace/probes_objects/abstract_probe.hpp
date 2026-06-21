#pragma once

#include "logger.hpp"
#include "bpf_header_includes.h"

struct all_bpf; // Forward declaration

namespace owlsm
{

enum class probe_type
{
    UNKNOWN,
    PROBE_MANAGER,
    LSM,
    FENTRY,
    TRACEPOINT,
    UPROBE
};

class AbstractProbe
{
public:
    virtual ~AbstractProbe() = default;

    AbstractProbe& operator=(const AbstractProbe& other)
    {
        if (this != &other)
        {
            m_skel = other.m_skel;
        }
        return *this;
    }

    virtual void bpfOpen() {};
    virtual void bpfLoad() {};
    virtual void bpfAttach() {};
    virtual void bpfDetach() {};
    virtual void bpfDestroy() {};
    virtual void setSkel(const std::shared_ptr<all_bpf>& skel) { m_skel = skel; }
    probe_type getProbeType() const { return m_type; }

protected:
    explicit AbstractProbe(probe_type type) : m_type(type) {}

    virtual void attachProbe(const bpf_program* program, bpf_link** link)
    {
        bpf_link* new_link = bpf_program__attach(program);
        if(!new_link)
        {
            throw std::runtime_error("failed to attach probe. errno: " + std::to_string(errno) + " program: " + bpf_program__name(program));
        }
        LOG_INFO("attached probe. program: " << bpf_program__name(program));
        *link = new_link;
    }

    void addProgramToArray(const bpf_program* program, const bpf_map* table)
    {
        int map_fd = bpf_map__fd(table);
        int prog_fd = bpf_program__fd(program);
        unsigned int idx = 0;
        if (bpf_map_update_elem(map_fd, &idx, &prog_fd, BPF_ANY) < 0)
        {
            throw std::runtime_error("failed to update program array. errno: " + std::to_string(errno) + " program: " + bpf_program__name(program));
        }
    }

    
    const probe_type m_type;
    std::shared_ptr<all_bpf> m_skel;
};
}