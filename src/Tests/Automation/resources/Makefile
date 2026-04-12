# ============================================================
# Automation Resources Makefile
# ============================================================

# ---- Variables from parent Makefile --------------------------
VERSION        ?= 1.0.0

# ---- Compiler ------------------------------------------------
CC             := gcc
# Match src/Userspace/Makefile (g++ on Ubuntu 20.04 does not accept -std=c++20).
CXX            := clang++

# Repo root: resources -> Automation -> Tests -> src -> owLSM
OWLSM_ROOT     := $(abspath $(CURDIR)/../../../..)
USERSPACE_DIR  := $(OWLSM_ROOT)/src/Userspace

# ---- Preprocessor Flags --------------------------------------
CPPFLAGS       :=

# ---- Compiler Flags ------------------------------------------
CFLAGS         := -Wall

ifdef DEBUG
    CFLAGS     += -O0 -g -DDEBUG
else
    CFLAGS     += -O2 -DNDEBUG
endif

# ---- Linker Flags --------------------------------------------
LDFLAGS        :=
LDLIBS         :=

# ---- Targets -------------------------------------------------
FBR_DIR        := flatbuffer_reader
# Executable lives inside FBR_DIR so the directory name does not clash with the binary.
FBR_EXE        := $(FBR_DIR)/flatbuffer_reader

TARGETS        := stdio_redirection related_process $(FBR_EXE)

# ---- Build Rules ---------------------------------------------
.PHONY: all clean

all: $(TARGETS)

stdio_redirection: stdio_redirection.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

related_process: related_process.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $< -o $@ $(LDFLAGS) $(LDLIBS)

$(FBR_EXE): $(FBR_DIR)/flatbuffer_reader.cpp $(FBR_DIR)/flatbuffer_to_json.cpp
	$(CXX) -std=c++20 -Wall -Wextra $(if $(DEBUG),-O0 -g,-O2 -DNDEBUG) \
		-I$(CURDIR)/$(FBR_DIR) -I$(USERSPACE_DIR) -I$(USERSPACE_DIR)/3rd_party \
		-o $@ $(FBR_DIR)/flatbuffer_reader.cpp $(FBR_DIR)/flatbuffer_to_json.cpp

clean:
	$(RM) $(TARGETS)
