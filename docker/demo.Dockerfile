FROM ubuntu:22.04@sha256:0e0a0fc6d18feda9db1590da249ac93e8d5abfea8f4c3c0c849ce512b5ef8982

ARG DEBIAN_FRONTEND=noninteractive
ARG TARGETARCH
ARG RENODE_URL=https://github.com/renode/renode/releases/download/v1.16.1/renode-1.16.1.linux-portable-dotnet.tar.gz
ARG RENODE_SHA256=00e113cdbd0f5354cf2f64bbe3f5a070d8958409542fca66e45ac97d982938c0

RUN test "${TARGETARCH}" = "amd64" || \
    { echo "ERROR: the demo image requires linux/amd64 (TARGETARCH=${TARGETARCH})" >&2; exit 1; }

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    libicu70 \
    python3 \
    python3-pip \
    python3-venv && \
    rm -rf /var/lib/apt/lists/*

RUN curl --fail --location --proto '=https' --tlsv1.2 "${RENODE_URL}" \
      --output /tmp/renode.tar.gz && \
    echo "${RENODE_SHA256}  /tmp/renode.tar.gz" | sha256sum -c - && \
    mkdir -p /opt/renode && \
    tar -xzf /tmp/renode.tar.gz -C /opt/renode --strip-components=1 && \
    rm /tmp/renode.tar.gz && \
    /opt/renode/renode --version

COPY requirements-demo.txt /opt/tardigrade-requirements/requirements-demo.txt

RUN python3 -m venv /opt/tardigrade-venv && \
    /opt/tardigrade-venv/bin/python -m pip install \
      --disable-pip-version-check \
      --no-cache-dir \
      --no-build-isolation \
      --require-hashes \
      --requirement /opt/tardigrade-requirements/requirements-demo.txt && \
    /opt/tardigrade-venv/bin/python -m pip check

ENV PATH=/opt/tardigrade-venv/bin:/opt/renode:${PATH}

WORKDIR /workspace

ENTRYPOINT ["python3", "scripts/run_demo.py", "--renode-test", "/opt/renode/renode-test"]
