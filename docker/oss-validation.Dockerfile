FROM ubuntu:22.04

ARG DEBIAN_FRONTEND=noninteractive
ARG TOOLCHAIN_VERSION=13.2.1-1.1
ARG TOOLCHAIN_URL=https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack/releases/download/v13.2.1-1.1/xpack-arm-none-eabi-gcc-13.2.1-1.1-linux-x64.tar.gz
ARG TOOLCHAIN_SHA256=1252a8cafe9237de27a765376697230368eec21db44dc3f1edeb8d838dabd530
ARG RENODE_URL=https://builds.renode.io/renode-latest.linux-portable.tar.gz

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    cmake \
    curl \
    device-tree-compiler \
    git \
    make \
    ninja-build \
    python3 \
    python3-pip \
    python3-venv \
    xz-utils && \
    rm -rf /var/lib/apt/lists/*

RUN curl -L "${TOOLCHAIN_URL}" -o /tmp/toolchain.tar.gz && \
    echo "${TOOLCHAIN_SHA256}  /tmp/toolchain.tar.gz" | sha256sum -c - && \
    mkdir -p /opt && \
    tar -xzf /tmp/toolchain.tar.gz -C /opt && \
    rm /tmp/toolchain.tar.gz && \
    mkdir -p /root/tools && \
    ln -s "/opt/xpack-arm-none-eabi-gcc-${TOOLCHAIN_VERSION}" /root/tools/gcc-arm-none-eabi-8-2018-q4-major

RUN curl -L "${RENODE_URL}" -o /tmp/renode.tar.gz && \
    mkdir -p /opt/renode && \
    tar -xzf /tmp/renode.tar.gz -C /opt/renode --strip-components=1 && \
    rm /tmp/renode.tar.gz

RUN python3 -m pip install --no-cache-dir --upgrade pip && \
    python3 -m pip install --no-cache-dir west robotframework && \
    python3 -m pip install --no-cache-dir -r /opt/renode/tests/requirements.txt

ENV GNUARMEMB_TOOLCHAIN_PATH=/root/tools/gcc-arm-none-eabi-8-2018-q4-major
ENV PATH=/root/tools/gcc-arm-none-eabi-8-2018-q4-major/bin:/opt/renode:${PATH}

WORKDIR /workspace

CMD ["/bin/bash"]
