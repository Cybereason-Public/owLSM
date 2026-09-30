# ============================================================
# Userspace Makefile
# ============================================================

# ---- Variables from parent Makefile --------------------------
VERSION        ?= 1.0.0
K8S            ?=

ifneq ($(K8S),)
ifneq ($(K8S),1)
$(error K8S must be 1 if set, got '$(K8S)')
endif
endif

# ---- Compiler ------------------------------------------------
CXX            := clang++

# ---- Preprocessor Flags --------------------------------------
CPPFLAGS       := -DOWLSM_VERSION_STR=\"$(VERSION)\" \
                  -I$(CURDIR) \
                  -I$(CURDIR)/../Kernel \
                  -I$(CURDIR)/../Kernel/Programs/syscall_monitoring \
                  -I$(CURDIR)/../Shared \
                  -I$(CURDIR)/3rd_party

# ---- Compiler Flags ------------------------------------------
CXXFLAGS       := -std=c++20 -Wall -Wextra \
                  -Wno-missing-field-initializers \
                  -Wno-unused-parameter

# Generate .d dependency files so header edits rebuild the right .o
DEPFLAGS       := -MMD -MP

ifdef DEBUG
    CXXFLAGS   += -O0 -g3 -ggdb -fno-omit-frame-pointer -fno-inline -fPIE -fstack-protector-strong -DDEBUG
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

K8S_CLIENT_GO_DIR := $(CURDIR)/kubernetes/client_go
K8S_CLIENT_SRC    := kubernetes/kubernetes_client.cpp
K8S_STUB_SRC      := kubernetes/kubernetes_client_stub.cpp

LDLIBS         := -lbpf -lelf -lz -lzstd -lssl -lcrypto -lsqlite3 -ldw -lbz2

# ---- Source / Objects ----------------------------------------
# Find all .cpp files recursively (exclude vendored 3rd_party).
SRC            := $(sort $(patsubst ./%,%,$(shell find . -name '*.cpp' -type f ! -path './3rd_party/*')))

ifeq ($(K8S),1)
CPPFLAGS       += -DOWLSM_KUBERNETES
SRC            := $(filter-out $(K8S_STUB_SRC),$(SRC))
LDFLAGS        += -L$(K8S_CLIENT_GO_DIR)
LDLIBS         += -lowlsm_k8s
K8S_LINK_DEPS  := k8s
OBJ_DIR        := .obj-k8s
else
SRC            := $(filter-out $(K8S_CLIENT_SRC),$(SRC))
K8S_LINK_DEPS  :=
OBJ_DIR        := .obj
endif

OBJS           := $(patsubst %.cpp,$(OBJ_DIR)/%.o,$(SRC))
DEPS           := $(OBJS:.o=.d)

# ---- Dependencies --------------------------------------------
BPF_SKEL       := ../Kernel/Programs/syscall_monitoring/all_bpf.skel.h
FEATURES_TEST_SKEL := ../Kernel/features_test.skel.h
SHARED_HDR     := ../Shared/events_structs.h
SCHEMA_INC     := configuration/schema.inc

# ---- Output --------------------------------------------------
BINARY         := owlsm

# ---- Build Rules ---------------------------------------------
.PHONY: all clean k8s

all: $(BINARY)

$(SCHEMA_INC): configuration/schema.json
	cd configuration && cp -a schema.json g_schema.json && xxd -i g_schema.json > schema.inc && rm -f g_schema.json

# Ensure generated headers exist before compiling any C++ TU.
$(OBJS): | $(BPF_SKEL) $(FEATURES_TEST_SKEL) $(SHARED_HDR) $(SCHEMA_INC)

$(OBJ_DIR)/%.o: %.cpp
	@mkdir -p $(dir $@)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(DEPFLAGS) -c $< -o $@

k8s:
	$(MAKE) -C $(K8S_CLIENT_GO_DIR)

$(BINARY): $(OBJS) $(K8S_LINK_DEPS)
	$(CXX) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) $(BINARY)
	$(RM) $(SCHEMA_INC)
	$(RM) -r .obj .obj-k8s
	$(MAKE) -C $(K8S_CLIENT_GO_DIR) clean

-include $(DEPS)
