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

# ---- Compilers -----------------------------------------------
BPF_CC         := clang
CXX            := clang++

# ---- BPF Compilation Flags -----------------------------------
BPF_CPPFLAGS   := -D__TARGET_ARCH_$(shell uname -m | sed 's/x86_64/x86/') \
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
                      $(USERSPACE_SRC_DIR)/probes_objects/uprobe_probe.cpp

# All source and object files
ALL_TEST_SRC   := $(KERNEL_TEST_SRC) $(USERSPACE_TEST_SRC) $(USERSPACE_IMPL_SRC) $(MAIN_SRC)
ALL_TEST_OBJ   := $(patsubst %.cpp,%.o,$(ALL_TEST_SRC))

# ---- Output Binary -------------------------------------------
TEST_BIN       := unit_tests

# ---- Build Rules ---------------------------------------------
.PHONY: all clean generate_constants

all: $(TEST_BIN)

generate_constants: $(CONSTANTS_H)

$(CONSTANTS_H): $(CONSTANTS_JSON)
	@echo "==> Generating constants.h from constants.json..."
	python3 $(SHARED_HDR_DIR)/generate_constants.py

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

# Compile kernel test C++ files to object files
$(KERNEL_TESTS_DIR)/%.o: $(KERNEL_TESTS_DIR)/%.cpp $(ALL_BPF_SKEL) $(SHARED_HDR_DIR)/events_structs.h
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# Compile userspace test C++ files to object files
$(USERSPACE_TESTS_DIR)/%.o: $(USERSPACE_TESTS_DIR)/%.cpp $(ALL_BPF_SKEL) $(SHARED_HDR_DIR)/events_structs.h
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# Compile userspace implementation C++ files to object files
$(USERSPACE_SRC_DIR)/%.o: $(USERSPACE_SRC_DIR)/%.cpp $(SCHEMA_INC)
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -c $< -o $@

# Link all object files into the test binary
$(TEST_BIN): $(ALL_TEST_OBJ)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $^ -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) $(BPF_OBJ) $(ALL_BPF_OBJ) $(ALL_BPF_SKEL) $(ALL_TEST_OBJ) $(TEST_BIN)
	$(RM) $(SCHEMA_INC)
	find $(KERNEL_TESTS_DIR) $(USERSPACE_TESTS_DIR) -type f -name '*.o' -delete 2>/dev/null || true
	find $(USERSPACE_SRC_DIR) -type f -name '*.o' -delete 2>/dev/null || true