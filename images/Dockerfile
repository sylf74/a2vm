# One image per pillar, built from the repository root (the CI job `images` builds all four):
#
#   docker build -f images/Dockerfile --build-arg PILLAR=verdict -t <registry>/verdict:<tag> .
#
# PILLAR is via, detect, verdict or dispatch. The image holds the common contract (ngvm), that pillar only
# (D12), and the default configuration of the version (/opt/ngvm/config). What a pillar needs of
# another one is a library of ngvm or an HTTP API, never the other pillar's package (v0.16.2). It runs as an
# unprivileged user and keeps no data: the chart deploy/charts/ngvm-tenant mounts the tenant's
# configuration, secrets and working volume.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ARG PILLAR
ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    NGVM_HOME=/opt/ngvm

# detect runs the read-only SSH collection: it needs the OpenSSH client.
RUN case "$PILLAR" in via|detect|verdict|dispatch) ;; *) echo "PILLAR must be via, detect, verdict or dispatch"; exit 1;; esac \
 && if [ "$PILLAR" = detect ]; then \
      apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-client \
      && rm -rf /var/lib/apt/lists/*; \
    fi

COPY ngvm /src/ngvm
COPY ${PILLAR} /src/${PILLAR}
COPY config /opt/ngvm/config

RUN extra=""; [ "$PILLAR" = detect ] && extra="[openvas,snmp]"; \
    pip install --quiet /src/ngvm "/src/${PILLAR}${extra}" \
 && rm -rf /src \
 && useradd --uid 10001 --create-home --home-dir /home/ngvm --shell /usr/sbin/nologin ngvm

USER 10001
WORKDIR /data
LABEL org.opencontainers.image.title="ngvm-${PILLAR}" \
      org.opencontainers.image.description="NGVM pillar ${PILLAR}"
