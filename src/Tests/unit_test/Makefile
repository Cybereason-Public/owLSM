# ============================================================
# Unit Tests Makefile
# ============================================================

# ---- Variables from parent Makefile --------------------------
VERSION        ?= 1.0.0

# Validate VERSION format
ifneq ($(words $(subst ., ,$(VERSION))),3)
$(error VERSION must be Major.Minor.Patch, got '$(VERSION)')
endif

# ---- Path Variables ------------------------------------------
KERNEL_HDR_DIR     := $(CURDIR)/../../Kernel
SHARED_HDR_DIR     := $(CURDIR)/../../Shared
USERSPACE_SRC_DIR  := $(CURDIR)/../../Userspace
KERNEL_TESTS_DIR   := $(CURDIR)/kernel
USERSPACE_TESTS_DIR := $(CURDIR)/userspace
SCHEMA_INC          := $(USERSPACE_SRC_DIR)/configuration/schema.inc
OBJ_DIR             := .obj

# ---- Compilers -----------------------------------------------
BPF_CC         := clang
CXX            := clang++

# ---- Architecture (libbpf expects x86 / arm64, not uname -m) -
UNAME_M        := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
BPF_TARGET_ARCH := x86
else ifeq ($(UNAME_M),aarch64)
BPF_TARGET_ARCH := arm64
else
$(error Unsupported architecture for eBPF build: $(UNAME_M))
endif

# ---- BPF Compilation Flags -----------------------------------
BPF_CPPFLAGS   := -D__TARGET_ARCH_$(BPF_TARGET_ARCH) \
                  -D__BPF_KERNEL__ \
                  -I$(KERNEL_TESTS_DIR) \
                  -I$(SHARED_HDR_DIR) \
                  -I$(KERNEL_HDR_DIR)

BPF_CFLAGS     := -O2 -g -Wall -Wno-unused-function -Wno-c23-extensions -target bpf \
                -Wno-address-of-packed-member \
                -fno-stack-protector \
                -fno-jump-tables \
                -fno-unroll-loops \
                -mcpu=v2 

# ---- C++ Compilation Flags -----------------------------------
CPPFLAGS       := -DOWLSM_VERSION_STR=\"$(VERSION)\" \
                  -I$(KERNEL_TESTS_DIR) \
                  -I$(USERSPACE_TESTS_DIR) \
                  -I$(SHARED_HDR_DIR) \
                  -I$(KERNEL_HDR_DIR) \
                  -I$(KERNEL_HDR_DIR)/Programs/syscall_monitoring \
                  -I$(USERSPACE_SRC_DIR) \
                  -I$(USERSPACE_SRC_DIR)/configuration \
                  -I$(USERSPACE_SRC_DIR)/globals \
                  -I$(USERSPACE_SRC_DIR)/3rd_party

CXXFLAGS       := -std=c++20 -Wall -Wextra \
                  -Wno-missing-field-initializers \
                  -Wno-unused-parameter \
                  -Wno-unused-result

# Generate .d dependency files so header edits rebuild the right .o
DEPFLAGS       := -MMD -MP

ifdef DEBUG
    CXXFLAGS   += -O0 -g -DDEBUG -fPIE -fstack-protector-strong
else
    CXXFLAGS   += -O2 -DNDEBUG -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE
endif

# ---- Linker Flags --------------------------------------------
LDFLAGS        := -pthread -static-libstdc++ -static-libgcc -Wl,-rpath,'$$ORIGIN/../lib' -Wl,--enable-new-dtags

ifdef DEBUG
    # Debug: no additional hardening flags
else
    LDFLAGS    += -Wl,-z,relro,-z,now -pie
endif

LDLIBS         := -lbpf -lelf -lz -lgtest -lsqlite3 -ldw -lbz2

# ---- EBPF Files ----------------------------------------------
LOCAL_BPF_SRC  := $(wildcard $(KERNEL_TESTS_DIR)/*.bpf.c)

BPF_SRC        := $(KERNEL_HDR_DIR)/common_maps.bpf.c \
                  $(KERNEL_HDR_DIR)/error_reports.bpf.c \
                  $(KERNEL_HDR_DIR)/event_and_rule_matcher.bpf.c \
                  $(KERNEL_HDR_DIR)/dfa.bpf.c \
                  $(LOCAL_BPF_SRC)

BPF_OBJ        := $(addprefix $(KERNEL_TESTS_DIR)/, $(notdir $(BPF_SRC:.bpf.c=.bpf.o)))
ALL_BPF_OBJ    := $(KERNEL_TESTS_DIR)/ebpf_unit_tests.o
ALL_BPF_SKEL   := $(KERNEL_TESTS_DIR)/ebpf_unit_tests.skel.h

# ---- Test Source Files ---------------------------------------
KERNEL_TEST_SRC    := $(wildcard $(KERNEL_TESTS_DIR)/*.cpp)
USERSPACE_TEST_SRC := $(shell find $(USERSPACE_TESTS_DIR) -type f -name '*.cpp' 2>/dev/null)
MAIN_SRC           := $(CURDIR)/main.cpp

# Userspace implementation files needed for tests
USERSPACE_IMPL_SRC := $(USERSPACE_SRC_DIR)/logger.cpp \
                      $(USERSPACE_SRC_DIR)/cmd_parser.cpp \
                      $(USERSPACE_SRC_DIR)/system_setup.cpp \
                      $(USERSPACE_SRC_DIR)/check_bpf_feature_availability.cpp \
                      $(USERSPACE_SRC_DIR)/raii_temp_files.cpp \
                      $(USERSPACE_SRC_DIR)/configuration/config_parser.cpp \
                      $(USERSPACE_SRC_DIR)/configuration/rules_parser.cpp \
                      $(USERSPACE_SRC_DIR)/rules_managment/rule_converter.cpp \
                      $(USERSPACE_SRC_DIR)/rules_managment/rules_into_bpf_maps.cpp \
                      $(USERSPACE_SRC_DIR)/rules_managment/dfa_builder.cpp \
                      $(USERSPACE_SRC_DIR)/probes_objects/probe_manager.cpp \
                      $(USERSPACE_SRC_DIR)/ringbuffers_messages_handlers.cpp \
                      $(USERSPACE_SRC_DIR)/events/event_to_json.cpp \
                      $(USERSPACE_SRC_DIR)/events/event_to_flatbuffer.cpp \
                      $(USERSPACE_SRC_DIR)/globals/global_objects.cpp \
                      $(USERSPACE_SRC_DIR)/globals/global_strings.cpp \
                      $(USERSPACE_SRC_DIR)/shell_detection/shells_db.cpp \
                      $(USERSPACE_SRC_DIR)/shell_detection/shells_finder.cpp \
                      $(USERSPACE_SRC_DIR)/shell_detection/shell_binary_info_extractor.cpp \
                      $(USERSPACE_SRC_DIR)/async_event_work/shell_async_worker.cpp \
                      $(USERSPACE_SRC_DIR)/probes_objects/uprobe_probe.cpp \
                      $(USERSPACE_SRC_DIR)/kubernetes/kubernetes_pod_cache.cpp \
                      $(USERSPACE_SRC_DIR)/kubernetes/kubernetes_client_stub.cpp

# Object files under .obj/ (do not drop .o into Userspace / test source trees)
KERNEL_TEST_OBJS    := $(patsubst $(KERNEL_TESTS_DIR)/%.cpp,$(OBJ_DIR)/kernel/%.o,$(KERNEL_TEST_SRC))
USERSPACE_TEST_OBJS := $(patsubst $(USERSPACE_TESTS_DIR)/%.cpp,$(OBJ_DIR)/userspace_tests/%.o,$(USERSPACE_TEST_SRC))
USERSPACE_IMPL_OBJS := $(patsubst $(USERSPACE_SRC_DIR)/%.cpp,$(OBJ_DIR)/userspace_impl/%.o,$(USERSPACE_IMPL_SRC))
MAIN_OBJ            := $(OBJ_DIR)/main.o
ALL_TEST_OBJ        := $(KERNEL_TEST_OBJS) $(USERSPACE_TEST_OBJS) $(USERSPACE_IMPL_OBJS) $(MAIN_OBJ)
DEPS                := $(ALL_TEST_OBJ:.o=.d)

# ---- Output Binary -------------------------------------------
TEST_BIN       := unit_tests

# ---- Build Rules ---------------------------------------------
.PHONY: all clean

all: $(TEST_BIN)

# Generate schema.inc from schema.json
$(SCHEMA_INC): $(USERSPACE_SRC_DIR)/configuration/schema.json
	cd $(USERSPACE_SRC_DIR)/configuration && cp -a schema.json g_schema.json && xxd -i g_schema.json > schema.inc && rm -f g_schema.json

# Compile BPF objects from kernel directory
$(KERNEL_TESTS_DIR)/%.bpf.o: $(KERNEL_HDR_DIR)/%.bpf.c
	$(BPF_CC) $(BPF_CPPFLAGS) $(BPF_CFLAGS) -c $< -o $@

# Compile BPF objects from kernel tests directory
$(KERNEL_TESTS_DIR)/%.bpf.o: $(KERNEL_TESTS_DIR)/%.bpf.c
	$(BPF_CC) $(BPF_CPPFLAGS) $(BPF_CFLAGS) -c $< -o $@

# Static-link all .bpf.o into one BPF ELF object
$(ALL_BPF_OBJ): $(BPF_OBJ)
	bpftool gen object $@ $^

# Generate skeleton from merged object
$(ALL_BPF_SKEL): $(ALL_BPF_OBJ)
	bpftool gen skeleton $< > $@

# Ensure generated headers exist before compiling any C++ TU.
$(ALL_TEST_OBJ): | $(ALL_BPF_SKEL) $(SHARED_HDR_DIR)/events_structs.h $(SCHEMA_INC)

$(OBJ_DIR)/main.o: $(MAIN_SRC)
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(OBJ_DIR)/kernel/%.o: $(KERNEL_TESTS_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(OBJ_DIR)/userspace_tests/%.o: $(USERSPACE_TESTS_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

$(OBJ_DIR)/userspace_impl/%.o: $(USERSPACE_SRC_DIR)/%.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

# Link all object files into the test binary
$(TEST_BIN): $(ALL_TEST_OBJ)
	$(CXX) $^ -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) $(BPF_OBJ) $(ALL_BPF_OBJ) $(ALL_BPF_SKEL) $(TEST_BIN)
	$(RM) $(SCHEMA_INC)
	$(RM) -r $(OBJ_DIR)
	# Remove legacy .o files from older Makefile layouts (if any remain).
	find $(KERNEL_TESTS_DIR) $(USERSPACE_TESTS_DIR) -type f -name '*.o' -delete 2>/dev/null || true
	find $(USERSPACE_SRC_DIR) -type f -name '*.o' -delete 2>/dev/null || true

-include $(DEPS)
