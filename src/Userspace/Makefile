# ============================================================
# Userspace Makefile
# ============================================================

# ---- Variables from parent Makefile --------------------------
VERSION        ?= 1.0.0

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

ifdef DEBUG
    CXXFLAGS   += -O0 -g3 -ggdb -fno-omit-frame-pointer -fno-inline -static-libstdc++ -static-libgcc -fPIE -fstack-protector-strong -DDEBUG 
else
    CXXFLAGS   += -O2 -DNDEBUG -D_FORTIFY_SOURCE=2 -fstack-protector-strong -fPIE -static-libstdc++ -static-libgcc
endif

# ---- Linker Flags --------------------------------------------
LDFLAGS        := -pthread -Wl,-rpath,'$$ORIGIN/../lib' -Wl,--enable-new-dtags

ifdef DEBUG
    # Debug: no additional hardening flags
else
    LDFLAGS    += -Wl,-z,relro,-z,now -pie
endif

LDLIBS         := -lbpf -lelf -lz -lzstd -lssl -lcrypto -lsqlite3 -ldw -lbz2 -ldl

# ---- Source Files --------------------------------------------
# Find all .cpp files recursively, ensuring main.cpp is first
SRC            := main.cpp $(filter-out ./main.cpp, $(shell find . -name "*.cpp" -type f))

# ---- Dependencies --------------------------------------------
BPF_SKEL       := ../Kernel/Programs/syscall_monitoring/all_bpf.skel.h
SHARED_HDR     := ../Shared/events_structs.h
SCHEMA_INC     := configuration/schema.inc

# ---- Output --------------------------------------------------
BINARY         := owlsm

# ---- Build Rules ---------------------------------------------
.PHONY: all clean

all: $(BINARY)

$(SCHEMA_INC): configuration/schema.json
	cd configuration && cp -a schema.json g_schema.json && xxd -i g_schema.json > schema.inc && rm -f g_schema.json

$(BINARY): $(SRC) $(BPF_SKEL) $(SHARED_HDR) $(SCHEMA_INC)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SRC) -o $@ $(LDFLAGS) $(LDLIBS)

clean:
	$(RM) $(BINARY)
	$(RM) configuration/schema.inc
	find . -type f -name '*.o' -delete 2>/dev/null || true

