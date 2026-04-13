# ============================================================
# Kernel (eBPF) Makefile
# ============================================================

# ---- Compiler ------------------------------------------------
BPF_CC         := clang

# ---- Path Variables ------------------------------------------
SHARED_DIR     := $(CURDIR)/../Shared
CONSTANTS_H    := $(SHARED_DIR)/constants.h
CONSTANTS_JSON := $(SHARED_DIR)/constants.json

# ---- BPF Compilation Flags (fixed, no mode variations) -------
BPF_CPPFLAGS   := -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/') \
                  -D__BPF_KERNEL__ \
                  -I$(CURDIR) \
                  -I$(CURDIR)/Programs/syscall_monitoring \
                  -I$(SHARED_DIR)

BPF_CFLAGS     := -O2 -g -Wall -Wno-unused-function -Wno-c23-extensions -target bpf \
                -Wno-address-of-packed-member \
                -fno-stack-protector \
                -fno-jump-tables \
                -fno-unroll-loops \
                -mcpu=v2

# ---- BPF Source Files ----------------------------------------
BPF_SRC        := common_maps.bpf.c \
                  error_reports.bpf.c \
                  event_and_rule_matcher.bpf.c \
                  dfa.bpf.c \
                  Programs/syscall_monitoring/on_chown.bpf.c \
                  Programs/syscall_monitoring/on_chmod.bpf.c \
                  Programs/syscall_monitoring/on_fork.bpf.c \
                  Programs/syscall_monitoring/on_exec.bpf.c \
                  Programs/syscall_monitoring/on_exit.bpf.c \
                  Programs/syscall_monitoring/on_syscall.bpf.c \
                  Programs/syscall_monitoring/on_file_create.bpf.c \
                  Programs/syscall_monitoring/on_mkdir.bpf.c \
                  Programs/syscall_monitoring/on_rmdir.bpf.c \
                  Programs/syscall_monitoring/on_write.bpf.c \
                  Programs/syscall_monitoring/on_read.bpf.c \
                  Programs/syscall_monitoring/on_unlink.bpf.c \
                  Programs/syscall_monitoring/on_rename.bpf.c \
                  Programs/network/on_tcp_incomming.bpf.c \
                  Programs/network/on_tcp_outgoing.bpf.c \
                  Programs/shell_command_monitoring/bash_shell_command.bpf.c \
                  Programs/shell_command_monitoring/zsh_shell_command.bpf.c \
                  Programs/shell_command_monitoring/dash/dash_shell_command.bpf.c

BPF_OBJ        := $(BPF_SRC:.bpf.c=.bpf.o)
BPF_MERGED     := Programs/syscall_monitoring/all_bpf.o
BPF_SKEL       := Programs/syscall_monitoring/all_bpf.skel.h

# ---- Build Rules ---------------------------------------------
.PHONY: all clean verifier_start verifier_end generate_constants

all: $(BPF_SKEL)

verifier_end:
	@rm -rf /sys/fs/bpf/dummy

verifier_start: verifier_end $(BPF_MERGED)
	@echo "==> Loading BPF programs for verification..."
	bpftool prog loadall $(BPF_MERGED) /sys/fs/bpf/dummy

generate_constants: $(CONSTANTS_H)

$(CONSTANTS_H): $(CONSTANTS_JSON)
	@echo "==> Generating constants.h from constants.json..."
	python3 $(CURDIR)/../Shared/generate_constants.py

# Compile each .bpf.c to .bpf.o
%.bpf.o: %.bpf.c $(CONSTANTS_H)
	$(BPF_CC) $(BPF_CPPFLAGS) $(BPF_CFLAGS) -c $< -o $@

# Merge all .bpf.o into one object
$(BPF_MERGED): $(BPF_OBJ)
	bpftool gen object $@ $^

# Generate skeleton from merged object
$(BPF_SKEL): $(BPF_MERGED)
	bpftool gen skeleton $< > $@

clean:
	$(RM) $(BPF_OBJ) $(BPF_MERGED) $(BPF_SKEL)
