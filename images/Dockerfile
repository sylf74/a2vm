# One image per pillar, built from the repository root (the CI job `images` builds all three):
#
#   docker build -f images/Dockerfile --build-arg PILLAR=verdict -t <registry>/verdict:<tag> .
#
# PILLAR is via, detect or verdict. The image holds the common contract (a2vm), that pillar (D12)
# and the default configuration of the version (/opt/a2vm/config). The via image also holds detect
# and verdict, as the watch's pipeline does: the watch matches the alerts to the client's assets
# with detect's a2vm.asset_matcher and dates their remediation with verdict's
# a2vm.remediation_timeline (a2vm.extensions); without them the watch on Kubernetes stops. It runs as an
# unprivileged user and keeps no data: the chart deploy/charts/a2vm-tenant mounts the tenant's
# configuration, secrets and working volume.
ARG PYTHON_IMAGE=python:3.12-slim
FROM ${PYTHON_IMAGE}

ARG PILLAR
ENV PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_ROOT_USER_ACTION=ignore \
    A2VM_HOME=/opt/a2vm

# detect runs the read-only SSH collection: it needs the OpenSSH client.
RUN case "$PILLAR" in via|detect|verdict) ;; *) echo "PILLAR must be via, detect or verdict"; exit 1;; esac \
 && if [ "$PILLAR" = detect ]; then \
      apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-client \
      && rm -rf /var/lib/apt/lists/*; \
    fi

COPY a2vm /src/a2vm
COPY via /src/via
COPY detect /src/detect
COPY verdict /src/verdict
COPY config /opt/a2vm/config

RUN case "$PILLAR" in \
      via) pkgs="/src/via /src/detect /src/verdict" ;; \
      detect) pkgs="/src/detect[openvas]" ;; \
      *) pkgs="/src/$PILLAR" ;; \
    esac \
 && pip install --quiet /src/a2vm $pkgs \
 && if [ "$PILLAR" = via ]; then \
      python -c "from importlib.metadata import entry_points as e; \
assert e(group='a2vm.asset_matcher') and e(group='a2vm.remediation_timeline'), 'watch extensions missing'"; \
    fi \
 && rm -rf /src \
 && useradd --uid 10001 --create-home --home-dir /home/a2vm --shell /usr/sbin/nologin a2vm

USER 10001
WORKDIR /data
LABEL org.opencontainers.image.title="a2vm-${PILLAR}" \
      org.opencontainers.image.description="A2VM pillar ${PILLAR}"
