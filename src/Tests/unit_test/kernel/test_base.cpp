#include "test_base.hpp"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

ebpf_unit_tests* BpfTestBase::m_shared_skel = nullptr;

void BpfTestBase::SetUpTestSuite()
{
    owlsm::SystemSetup::cleanupOwlsmDirectory(true);
    m_shared_skel = loadSkeleton();
}

void BpfTestBase::TearDownTestSuite()
{
    if (m_shared_skel)
    {
        ebpf_unit_tests__destroy(m_shared_skel);
        m_shared_skel = nullptr;
    }
    owlsm::SystemSetup::cleanupOwlsmDirectory(true);
}

void BpfTestBase::SetUp()
{
    skel = m_shared_skel;
    if (!skel)
    {
        throw std::runtime_error("BPF skeleton was not loaded");
    }
    resetMaps(skel);
}

ebpf_unit_tests* BpfTestBase::loadSkeleton()
{
    bpf_object_open_opts open_opts = {};
    open_opts.sz = sizeof(open_opts);
    open_opts.pin_root_path = owlsm::globals::SYS_FS_BPF_OWLSM_PATH;

    ebpf_unit_tests* const skeleton = ebpf_unit_tests__open_opts(&open_opts);
    if (!skeleton)
    {
        throw std::runtime_error("Failed to open BPF skeleton. errno: " + std::to_string(errno));
    }

    const int err = ebpf_unit_tests__load(skeleton);
    if (err)
    {
        ebpf_unit_tests__destroy(skeleton);
        throw std::runtime_error("Failed to load BPF skeleton. errno: " + std::to_string(err));
    }
    return skeleton;
}

void BpfTestBase::resetMaps(ebpf_unit_tests* const skeleton)
{
    bpf_map* map = nullptr;
    bpf_object__for_each_map(map, skeleton->obj)
    {
        if (!shouldResetMap(map))
        {
            continue;
        }
        resetMap(map);
    }
}

bool BpfTestBase::shouldResetMap(const struct bpf_map* const map)
{
    if (bpf_map__is_internal(map))
    {
        return false;
    }

    switch (bpf_map__type(map))
    {
        case BPF_MAP_TYPE_HASH:
        case BPF_MAP_TYPE_PERCPU_HASH:
        case BPF_MAP_TYPE_LRU_HASH:
        case BPF_MAP_TYPE_LRU_PERCPU_HASH:
        case BPF_MAP_TYPE_ARRAY:
        case BPF_MAP_TYPE_PERCPU_ARRAY:
            return true;
        default:
            return false;
    }
}

void BpfTestBase::resetMap(struct bpf_map* const map)
{
    const int fd = bpf_map__fd(map);
    if (fd < 0)
    {
        throw std::runtime_error(std::string("bpf_map__fd failed for ") + bpf_map__name(map));
    }

    const enum bpf_map_type type = bpf_map__type(map);
    if (type == BPF_MAP_TYPE_HASH || type == BPF_MAP_TYPE_PERCPU_HASH
        || type == BPF_MAP_TYPE_LRU_HASH || type == BPF_MAP_TYPE_LRU_PERCPU_HASH)
    {
        deleteAllKeys(fd, bpf_map__key_size(map));
        return;
    }

    if (zeroAllEntries(map))
    {
        return;
    }

    // prevention.cpp freezes this map on purpose. Later tests do not read it.
    if (std::strcmp(bpf_map__name(map), "ebpf_program_start_time") == 0)
    {
        return;
    }
    throw std::runtime_error(std::string("BPF map is frozen: ") + bpf_map__name(map));
}

void BpfTestBase::deleteAllKeys(const int fd, const __u32 key_size)
{
    if (key_size == 0)
    {
        return;
    }

    std::vector<std::byte> key(key_size);
    std::vector<std::byte> next_key(key_size);
    if (bpf_map_get_next_key(fd, nullptr, key.data()) != 0)
    {
        return;
    }

    while (true)
    {
        const int has_next = bpf_map_get_next_key(fd, key.data(), next_key.data());
        errno = 0;
        if (bpf_map_delete_elem(fd, key.data()) < 0)
        {
            const int err = errno != 0 ? errno : EPERM;
            throw std::runtime_error("bpf_map_delete_elem failed. errno: " + std::to_string(err));
        }
        if (has_next != 0)
        {
            break;
        }
        key.swap(next_key);
    }
}

bool BpfTestBase::zeroAllEntries(struct bpf_map* const map)
{
    const int fd = bpf_map__fd(map);
    const __u32 value_size = bpf_map__value_size(map);
    const __u32 max_entries = bpf_map__max_entries(map);
    const __u32 key_size = bpf_map__key_size(map);
    const bool per_cpu = isPerCpuMap(bpf_map__type(map));
    if (max_entries == 0 || value_size == 0 || key_size == 0)
    {
        return true;
    }

    const int cpu_count = per_cpu ? libbpf_num_possible_cpus() : 1;
    if (cpu_count <= 0)
    {
        throw std::runtime_error("libbpf_num_possible_cpus failed");
    }

    const size_t slot_size = per_cpu
        ? static_cast<size_t>((value_size + 7u) & ~7u) * static_cast<size_t>(cpu_count)
        : static_cast<size_t>(value_size);

    if (!per_cpu && key_size == sizeof(__u32) && max_entries > 1)
    {
        std::vector<__u32> keys(max_entries);
        for (__u32 index = 0; index < max_entries; ++index)
        {
            keys[index] = index;
        }
        std::vector<std::byte> values(static_cast<size_t>(max_entries) * slot_size);
        __u32 count = max_entries;
        bpf_map_batch_opts opts = {};
        opts.sz = sizeof(opts);
        opts.elem_flags = BPF_ANY;
        errno = 0;
        if (bpf_map_update_batch(fd, keys.data(), values.data(), &count, &opts) == 0)
        {
            return true;
        }
        const int err = errno != 0 ? errno : EPERM;
        if (err == EPERM || err == EACCES)
        {
            return false;
        }
    }

    std::vector<std::byte> value(slot_size);
    std::vector<std::byte> key(key_size);
    for (__u32 index = 0; index < max_entries; ++index)
    {
        std::memset(key.data(), 0, key.size());
        const size_t index_bytes = sizeof(index) < key.size() ? sizeof(index) : key.size();
        std::memcpy(key.data(), &index, index_bytes);

        errno = 0;
        if (bpf_map_update_elem(fd, key.data(), value.data(), BPF_ANY) < 0)
        {
            const int err = errno != 0 ? errno : EPERM;
            if (err == EPERM || err == EACCES)
            {
                return false;
            }
            throw std::runtime_error(std::string("bpf_map_update_elem failed for ") + bpf_map__name(map)
                + ". errno: " + std::to_string(err));
        }
    }
    return true;
}

bool BpfTestBase::isPerCpuMap(const enum bpf_map_type type)
{
    switch (type)
    {
        case BPF_MAP_TYPE_PERCPU_HASH:
        case BPF_MAP_TYPE_PERCPU_ARRAY:
        case BPF_MAP_TYPE_LRU_PERCPU_HASH:
            return true;
        default:
            return false;
    }
}
