FROM ubuntu:18.04

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
    # Add GCC 9 PPA (Ubuntu 18.04 defaults to GCC 7, we need GCC 9 to match Ubuntu 20.04)
    add-apt-repository ppa:ubuntu-toolchain-r/test && \
    add-apt-repository universe && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        gcc-9 \
        g++-9 \
        libstdc++-10-dev \
        git \
        pkg-config \
        xxd \
        xz-utils \
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
        cmake \
        # misc
        make && \
    # Set GCC 9 as the default gcc/g++
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 100 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-9 100 && \
    rm -rf /var/lib/apt/lists/*

# Install LLVM 18 / Clang 18 from upstream Ubuntu 18.04 tarball.
# apt.llvm.org bionic packages are frozen and currently have unresolved deps on 18.04.
RUN curl -fL "https://github.com/llvm/llvm-project/releases/download/llvmorg-18.1.8/clang+llvm-18.1.8-x86_64-linux-gnu-ubuntu-18.04.tar.xz" -o /tmp/llvm18.tar.xz && \
    mkdir -p /opt/llvm-18 && \
    tar -xJf /tmp/llvm18.tar.xz -C /opt/llvm-18 --strip-components=1 && \
    rm -f /tmp/llvm18.tar.xz && \
    ln -sf /opt/llvm-18/bin/clang /usr/local/bin/clang && \
    ln -sf /opt/llvm-18/bin/clang++ /usr/local/bin/clang++ && \
    ln -sf /opt/llvm-18/bin/clang /usr/local/bin/clang-18 && \
    ln -sf /opt/llvm-18/bin/clang++ /usr/local/bin/clang++-18 && \
    ln -sf /opt/llvm-18/bin/llvm-strip /usr/local/bin/llvm-strip && \
    ln -sf /opt/llvm-18/bin/llvm-objcopy /usr/local/bin/llvm-objcopy && \
    ln -sf /opt/llvm-18/bin/llvm-objdump /usr/local/bin/llvm-objdump && \
    ln -sf /opt/llvm-18/bin/llvm-ar /usr/local/bin/llvm-ar && \
    ln -sf /opt/llvm-18/bin/llvm-nm /usr/local/bin/llvm-nm && \
    ln -sf /opt/llvm-18/bin/llvm-readelf /usr/local/bin/llvm-readelf

# Build & install Google Test (Ubuntu 18.04's libgtest-dev ships source only)
RUN cd /usr/src/googletest && \
    cmake -DCMAKE_CXX_COMPILER=g++-9 . && \
    make -j"$(nproc)" && \
    find . -name '*.a' -exec cp {} /usr/lib/ \; && \
    ldconfig

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

ENV LD_LIBRARY_PATH="/opt/llvm-18/lib:/opt/llvm-18/lib/x86_64-unknown-linux-gnu" \
    PATH="/opt/llvm-18/bin:/usr/local/bin:$PATH"