# ============================================================
# Main Makefile for OWLSM Project
# ============================================================

# ---- Configuration Variables ---------------------------------
# Set DEBUG=1 for debug builds: make DEBUG=1
# Leave unset for release builds: make
VERSION        ?= 1.0.0

# Validate VERSION format (X.Y.Z)
ifneq ($(words $(subst ., ,$(VERSION))),3)
$(error VERSION must be Major.Minor.Patch, got '$(VERSION)')
endif

# ---- Export variables to sub-makefiles -----------------------
export DEBUG
export VERSION

# ---- Directories ---------------------------------------------
SRC_DIR        := src
BUILD_DIR      := build
KERNEL_DIR     := $(SRC_DIR)/Kernel
USERSPACE_DIR  := $(SRC_DIR)/Userspace
TEST_DIR       := $(SRC_DIR)/Tests
UNIT_TEST_DIR  := $(TEST_DIR)/unit_test
AUTOMATION_DIR := $(TEST_DIR)/Automation
AUTOMATION_RESOURCES_DIR := $(AUTOMATION_DIR)/resources
SCRIPTS_DIR    := scripts

# ---- Binary Paths --------------------------------------------
USER_BIN       := $(USERSPACE_DIR)/owlsm
TEST_BIN       := $(UNIT_TEST_DIR)/unit_tests

# ---- Install Paths -------------------------------------------
INSTALL_DIR    := $(BUILD_DIR)/owlsm
TEST_INSTALL_DIR := $(BUILD_DIR)/unit_tests

# ---- Phony Targets -------------------------------------------
.PHONY: all clean test tarball automation help kernel userspace
.DEFAULT_GOAL := all

# ---- Build Targets -------------------------------------------
all: kernel userspace
	@python3 $(SCRIPTS_DIR)/package.py owlsm

kernel:
	@echo "==> Building Kernel (eBPF)..."
	@$(MAKE) -C $(KERNEL_DIR)

userspace: kernel
	@echo "==> Building Userspace..."
	@$(MAKE) -C $(USERSPACE_DIR)

test: kernel
	@echo "==> Building unit tests..."
	@$(MAKE) -C $(UNIT_TEST_DIR)
	@python3 $(SCRIPTS_DIR)/package.py unit_tests

tarball: all
	@echo "==> Creating tarball..."
	@tar -czf $(BUILD_DIR)/owlsm-$(VERSION).tar.gz -C $(BUILD_DIR) owlsm
	@echo "==> Tarball created: $(BUILD_DIR)/owlsm-$(VERSION).tar.gz"

automation:
	@echo "==> Building automation resources..."
	@$(MAKE) -C $(AUTOMATION_RESOURCES_DIR)
	@rm -rf $(AUTOMATION_DIR)/owlsm
	@cp -a $(INSTALL_DIR) $(AUTOMATION_DIR)/owlsm

clean:
	@echo "==> Cleaning Kernel..."
	@$(MAKE) -C $(KERNEL_DIR) clean
	@echo "==> Cleaning Userspace..."
	@$(MAKE) -C $(USERSPACE_DIR) clean
	@echo "==> Cleaning Tests..."
	@$(MAKE) -C $(UNIT_TEST_DIR) clean
	@$(MAKE) -C $(AUTOMATION_RESOURCES_DIR) clean
	@echo "==> Cleaning build directory..."
	@rm -rf $(BUILD_DIR)

help:
	@echo "OWLSM Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all        - Build and package owlsm (default) → build/owlsm/"
	@echo "  kernel     - Build eBPF kernel code"
	@echo "  userspace  - Build userspace binary"
	@echo "  test       - Build and package unit tests → build/unit_tests/"
	@echo "  tarball    - Create release tarball (depends on all)"
	@echo "  automation - Build and setup automation tests"
	@echo "  clean      - Clean all build artifacts"
	@echo "  help       - Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  DEBUG      - Set to 1 for debug build (default: unset = release)"
	@echo "  VERSION    - Version string X.Y.Z (default: $(VERSION))"
	@echo ""
	@echo "Examples:"
	@echo "  make -j\$$(nproc)              # Release build"
	@echo "  make DEBUG=1 -j\$$(nproc)      # Debug build"
	@echo "  make tarball VERSION=2.0.0    # Release tarball"
	@echo "  make test -j\$$(nproc)         # Build + package unit tests"
	@echo "  make automation -j\$$(nproc)   # Build + setup automation"

# Test commit
