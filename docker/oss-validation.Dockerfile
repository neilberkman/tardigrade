FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
ARG TOOLCHAIN_VERSION=13.2.1-1.1
ARG TOOLCHAIN_URL=https://github.com/xpack-dev-tools/arm-none-eabi-gcc-xpack/releases/download/v13.2.1-1.1/xpack-arm-none-eabi-gcc-13.2.1-1.1-linux-x64.tar.gz
ARG TOOLCHAIN_SHA256=1252a8cafe9237de27a765376697230368eec21db44dc3f1edeb8d838dabd530
ARG RENODE_URL=https://github.com/renode/renode/releases/download/v1.16.1/renode-1.16.1.linux-portable-dotnet.tar.gz
ARG RENODE_SHA256=00e113cdbd0f5354cf2f64bbe3f5a070d8958409542fca66e45ac97d982938c0

RUN test "${TARGETARCH}" = "amd64" || \
    { echo "ERROR: OSS validation supports only linux/amd64 (TARGETARCH=${TARGETARCH})" >&2; exit 1; }

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

RUN curl --fail --location --proto '=https' --tlsv1.2 "${TOOLCHAIN_URL}" -o /tmp/toolchain.tar.gz && \
    echo "${TOOLCHAIN_SHA256}  /tmp/toolchain.tar.gz" | sha256sum -c - && \
    mkdir -p /opt && \
    tar -xzf /tmp/toolchain.tar.gz -C /opt && \
    rm /tmp/toolchain.tar.gz && \
    mkdir -p /root/tools && \
    ln -s "/opt/xpack-arm-none-eabi-gcc-${TOOLCHAIN_VERSION}" /root/tools/gcc-arm-none-eabi-8-2018-q4-major

RUN curl --fail --location --proto '=https' --tlsv1.2 "${RENODE_URL}" -o /tmp/renode.tar.gz && \
    echo "${RENODE_SHA256}  /tmp/renode.tar.gz" | sha256sum -c - && \
    mkdir -p /opt/renode && \
    tar -xzf /tmp/renode.tar.gz -C /opt/renode --strip-components=1 && \
    rm /tmp/renode.tar.gz

COPY requirements.txt requirements-renode-constraints.txt requirements-oss-build.txt /opt/tardigrade-requirements/

RUN python3 -m venv /opt/tardigrade-venv && \
    /opt/tardigrade-venv/bin/python -m pip install --no-cache-dir \
      -c /opt/tardigrade-requirements/requirements-renode-constraints.txt \
      -r /opt/renode/tests/requirements.txt && \
    /opt/tardigrade-venv/bin/python -m pip install --no-cache-dir \
      -r /opt/tardigrade-requirements/requirements.txt \
      -r /opt/tardigrade-requirements/requirements-oss-build.txt && \
    /opt/tardigrade-venv/bin/python -m pip check

ENV GNUARMEMB_TOOLCHAIN_PATH=/root/tools/gcc-arm-none-eabi-8-2018-q4-major
ENV PATH=/opt/tardigrade-venv/bin:/root/tools/gcc-arm-none-eabi-8-2018-q4-major/bin:/opt/renode:${PATH}

WORKDIR /workspace

CMD ["/bin/bash"]
