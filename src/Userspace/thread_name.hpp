#pragma once

#include "logger.hpp"

#include <cstring>
#include <pthread.h>

namespace owlsm
{

class ThreadName
{
public:
    static void setCurrent(const char* name)
    {
        set(pthread_self(), name);
    }

    static void set(pthread_t thread, const char* name)
    {
        if (name == nullptr || std::strlen(name) > 15)
        {
            LOG_ERROR("Failed to name thread");
            return;
        }

        if (pthread_setname_np(thread, name) != 0)
        {
            LOG_ERROR("Failed to name thread " << name);
        }
    }
};

}
