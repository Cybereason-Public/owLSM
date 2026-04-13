#pragma once

#if defined(__TARGET_ARCH_x86)
#include "vmlinux_x86.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux_arm64.h"
#else
#error "Unsupported architecture: define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif
