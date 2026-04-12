FROM ubuntu:20.04

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
        make && \
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

# Install flatc (FlatBuffers compiler) v25.12.19
RUN curl -LO https://github.com/google/flatbuffers/releases/download/v25.12.19/Linux.flatc.binary.clang++-18.zip && \
    unzip Linux.flatc.binary.clang++-18.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/flatc && \
    rm Linux.flatc.binary.clang++-18.zip

ENV PATH="/usr/local/bin:$PATH"