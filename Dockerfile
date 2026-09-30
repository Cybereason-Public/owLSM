FROM ubuntu:20.04

ARG TARGETARCH

ENV DEBIAN_FRONTEND=noninteractive

# Base tools and enable 'universe' (needed for clang-18, libbpf-dev, etc.)
RUN rm -rf /var/lib/apt/lists/* && \
    apt-get clean && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        gnupg \
        software-properties-common && \
    # Add LLVM's official apt repository for clang-18
    curl -fsSL https://apt.llvm.org/llvm-snapshot.gpg.key | gpg --dearmor -o /usr/share/keyrings/llvm.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/llvm.gpg] http://apt.llvm.org/focal/ llvm-toolchain-focal-18 main" > /etc/apt/sources.list.d/llvm.list && \
    add-apt-repository universe && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        git \
        unzip \
        pkg-config \
        xxd \
        # Clang / LLVM 18
        clang-18 \
        clang-tools-18 \
        llvm-18 \
        llvm-18-dev \
        lld-18 \
        # libbpf-dev (for libbpf)
        libelf-dev \
        libdw-dev \
        # zlib (shared + static)
        zlib1g-dev \
        # zstd (shared + static)
        libzstd-dev \
        # libssl-dev (for OpenSSL build)
        libssl-dev \
        # sqlite3 (for SQLite build)
        libsqlite3-dev \
        # libbz2 (transitive dep of libdw; link directly so RUNPATH finds it)
        libbz2-dev \
        # libs for tests
        libgtest-dev \
        googletest \
        # misc
        make \
        patchelf && \
    rm -rf /var/lib/apt/lists/*

# Make clang-18 and LLVM tools the default (without version suffix)
RUN update-alternatives --install /usr/bin/clang clang /usr/bin/clang-18 100 && \
    update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-18 100 && \
    ln -sf /usr/bin/llvm-strip-18 /usr/bin/llvm-strip && \
    ln -sf /usr/bin/llvm-objcopy-18 /usr/bin/llvm-objcopy && \
    ln -sf /usr/bin/llvm-objdump-18 /usr/bin/llvm-objdump && \
    ln -sf /usr/bin/llvm-ar-18 /usr/bin/llvm-ar && \
    ln -sf /usr/bin/llvm-nm-18 /usr/bin/llvm-nm && \
    ln -sf /usr/bin/llvm-readelf-18 /usr/bin/llvm-readelf

ENV CC=clang \
    CXX=clang++ \
    CLANG=clang

WORKDIR /tmp

# Build & install libbpf v1.5.0 (Ubuntu 20.04's libbpf 0.5 is too old)
RUN git clone --depth=1 --branch v1.5.0 https://github.com/libbpf/libbpf.git && \
    make -C libbpf/src -j"$(nproc)" && \
    make -C libbpf/src install && \
    make -C libbpf/src install_uapi_headers && \
    ldconfig && \
    rm -rf libbpf

# Build & install bpftool v7.5.0
RUN git clone --depth=1 --branch v7.5.0 --recurse-submodules https://github.com/libbpf/bpftool.git && \
    make -C bpftool/src -j"$(nproc)" && \
    install -m 0755 bpftool/src/bpftool /usr/local/bin/bpftool && \
    rm -rf bpftool

# Install uv globally (to /usr/local/bin) so any user can access it
ENV UV_INSTALL_DIR=/usr/local/bin
RUN curl -LsSf https://astral.sh/uv/install.sh | sh && \
    /usr/local/bin/uv python install 3.10 && \
    ln -sf $(/usr/local/bin/uv python find 3.10) /usr/local/bin/python3 && \
    ln -sf $(/usr/local/bin/uv python find 3.10) /usr/local/bin/python

# flatc: official Linux zip is x86_64-only; skip on aarch64 (generated headers are checked in)
RUN if [ -z "${TARGETARCH}" ] || [ "${TARGETARCH}" = "amd64" ]; then \
        curl -LO https://github.com/google/flatbuffers/releases/download/v25.12.19/Linux.flatc.binary.clang++-18.zip && \
        unzip Linux.flatc.binary.clang++-18.zip -d /usr/local/bin/ && \
        chmod +x /usr/local/bin/flatc && \
        rm Linux.flatc.binary.clang++-18.zip; \
    fi

ENV PATH="/usr/local/bin:$PATH"

# Official Go toolchain from go.dev. Used to compile the thin client-go C ABI wrapper
ARG GO_VERSION=1.26.6
RUN set -eux; \
    go_arch="${TARGETARCH}"; \
    if [ -z "${go_arch}" ]; then \
        case "$(uname -m)" in \
            x86_64) go_arch=amd64 ;; \
            aarch64) go_arch=arm64 ;; \
            *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
        esac; \
    fi; \
    case "${go_arch}" in \
        amd64) go_sha256="708effb774be8237570d0add163225abbdfaf4fca28b2611df167beba4feef89" ;; \
        arm64) go_sha256="d0507e9e9d7fe012aae570108cbd76c15de879e17130ab8cb90d4d7445cb1f2e" ;; \
        *) echo "Unsupported TARGETARCH=${go_arch}" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" -o /tmp/go.tgz; \
    echo "${go_sha256}  /tmp/go.tgz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz

ENV PATH="/usr/local/go/bin:${PATH}" \
    GOMODCACHE=/usr/local/gomodcache

# Prefetch client-go into the image module cache (no official prebuilt .so exists).
RUN mkdir -p "${GOMODCACHE}" /tmp/owlsm-client-go && \
    cd /tmp/owlsm-client-go && \
    go mod init owlsm/kubernetes/client_go && \
    go get k8s.io/client-go@v0.32.3 k8s.io/apimachinery@v0.32.3 && \
    rm -rf /tmp/owlsm-client-go
