#pragma once

#if defined(__TARGET_ARCH_x86)
#include "vmlinux-x86_64.h"
#elif defined(__TARGET_ARCH_arm64)
#include "vmlinux-aarch64.h"
#else
#error "Unsupported architecture: define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif

// Some arch vmlinux dumps omit TASK_COMM_LEN (Linux task comm is 16 bytes).
#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif
