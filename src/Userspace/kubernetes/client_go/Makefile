# Thin client-go wrapper built as a C shared library.
# gcc is used for cgo even when the rest of owLSM is compiled with clang.

.PHONY: all clean

GO           ?= go
CC           := gcc
CGO_ENABLED  := 1
GOPROXY      ?= https://proxy.golang.org,direct
PROJECT_ROOT := $(abspath $(CURDIR)/../../../..)
GOCACHE      ?= $(PROJECT_ROOT)/build/.gocache
GOMODCACHE   ?= $(PROJECT_ROOT)/build/.gomodcache
GOTMPDIR     ?= $(PROJECT_ROOT)/build/.gotmp

export CC
export CGO_ENABLED
export GOPROXY
export GOCACHE
export GOMODCACHE
export GOTMPDIR
export TMPDIR := $(GOTMPDIR)

SO           := libowlsm_k8s.so
CGO_HEADER   := libowlsm_k8s.h
SRCS         := wrapper.go go.mod owlsm_k8s.h

all: $(SO)

$(SO): $(SRCS)
	mkdir -p "$(GOCACHE)" "$(GOTMPDIR)"
	$(GO) mod tidy
	$(GO) build -trimpath -buildvcs=false -ldflags="-s -w" -buildmode=c-shared -o $@ .
	$(RM) $(CGO_HEADER)

clean:
	$(RM) $(SO) $(CGO_HEADER)
	$(RM) -r "$(GOTMPDIR)"
