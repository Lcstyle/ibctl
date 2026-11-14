# syntax=docker/dockerfile:1.7
# ibctl — IBC replacement for IB Gateway/TWS automation
# Self-contained build following gnzsnz/ib-gateway-docker's proven process,
# but without IBC. ibctl replaces it entirely.
#
# BuildKit cache mounts (RUN --mount=type=cache) are used throughout to
# speed up apt-get, cargo, and pip across CI runs. Requires BuildKit
# (docker buildx uses it by default).
#
# Two build modes:
#   Fast (pre-built release):
#     docker build --build-arg IBCTL_VERSION=v0.1.0 -t ibctl .
#   From source (no release available):
#     docker build -t ibctl .

ARG IB_GATEWAY_VERSION=10.50.1f
ARG IB_GATEWAY_CHANNEL=stable
# sha256 of the installer for IB_GATEWAY_VERSION. Set together with the
# version (the weekly upgrade job does both); scripts/gateway-installer.sh
# keeps the file in the installer store and refuses a checksum that does not
# match.
ARG IB_GATEWAY_SHA256=2b868362238cef71ee0f83068c6e5777ae38f59eae585ff84f75ca1d8b2e06d5
ARG IBCTL_VERSION=""

##############################################################################
# Stage 1: Setup — download and install IB Gateway
# Follows gnzsnz/ib-gateway-docker's exact process (minus IBC)
##############################################################################
FROM ubuntu:24.04 AS setup

ARG IB_GATEWAY_VERSION
ARG IB_GATEWAY_CHANNEL
ARG IB_GATEWAY_SHA256
ARG TARGETARCH
ARG DEBIAN_FRONTEND=noninteractive
ARG IB_GATEWAY_FILE="ibgateway-${IB_GATEWAY_VERSION}-standalone-linux-x64.sh"
# Where the installer comes from. IB serves only each channel's current build,
# at a URL that names no version, so the pinned IB_GATEWAY_VERSION needs a store
# laid out as <store>/<version>/<file> (scripts/gateway-installer.sh keeps one).
# Pass --build-arg IB_GATEWAY_STORE=<base URL>, or put that URL on the one line
# of .gateway-store at the repo root. IB_GATEWAY_URL overrides both with a
# direct link to the installer. Either way the file must match
# IB_GATEWAY_SHA256.
#
# With no store and no URL, the build installs IB's current build for
# IB_GATEWAY_CHANNEL straight from IB, whatever its version. IB publishes no
# checksum for it, so the build prints its sha256 instead of checking one.
ARG IB_GATEWAY_STORE=""
ARG IB_GATEWAY_URL=""
# aarch64 JDK (only used on ARM)
ARG ZULU_NAME=zulu17.60.17-ca-fx-jre17.0.16-linux_aarch64
ARG ZULU_FILE=${ZULU_NAME}.tar.gz
ARG ZULU_URL=https://cdn.azul.com/zulu/bin/${ZULU_FILE}

WORKDIR /tmp/setup
# The installer store's base URL when IB_GATEWAY_STORE isn't passed (empty
# when this build has no store; see above).
COPY .gateway-store /tmp/ibctl-build/gateway-store

# Two-phase mirror setup:
#  1) apt-get update over HTTP against the base image's default sources
#     (archive.ubuntu.com / security.ubuntu.com), then install
#     ca-certificates so we can switch to HTTPS. We can't use HTTPS yet
#     because the base image ships without a CA trust store.
#  2) Rewrite http:// → https:// and re-update. From now on package
#     fetches are authenticated + integrity-checked via TLS.
#
# Rationale for using archive.ubuntu.com throughout instead of a regional
# mirror: an intermediate mirror is a single point of failure. When a
# regional mirror becomes unreachable from the build host, every rebuild
# fails at phase 1. Sticking to archive.ubuntu.com means a rebuild has
# exactly one external dependency (Ubuntu's canonical origin), not two.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update -y \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update -y \
    && apt-get install --no-install-recommends --yes curl \
    # Validate supported architectures
    && if [ "${TARGETARCH}" != "amd64" ] && [ "${TARGETARCH}" != "arm64" ]; then \
        echo "Unsupported Docker target architecture: ${TARGETARCH}" >&2; \
        exit 1; \
    fi \
    # arm64: download Zulu JDK
    && if [ "${TARGETARCH}" = "arm64" ]; then \
        curl -sSLO ${ZULU_URL} && \
        tar -xzf ${ZULU_FILE} -C /usr/local/ && \
        ln -s /usr/local/${ZULU_NAME} /usr/local/zulu17; \
    fi \
    # Download the installer. From a store or IB_GATEWAY_URL it is the pinned
    # build, checked against the pinned checksum (not a checksum served next
    # to it, which proves only that the two agree). With neither, it is IB's
    # current build for the channel, at the version IB announces for it.
    && store="${IB_GATEWAY_STORE:-$(tr -d ' \t\r\n' < /tmp/ibctl-build/gateway-store)}" \
    && url="${IB_GATEWAY_URL:-${store:+${store}/${IB_GATEWAY_VERSION}/${IB_GATEWAY_FILE}}}" \
    && if [ -n "${url}" ]; then \
        test -n "${IB_GATEWAY_SHA256}" \
        && gw_version="${IB_GATEWAY_VERSION}" \
        && curl -fsSL -o installer.sh "${url}" \
        && echo "${IB_GATEWAY_SHA256}  installer.sh" | sha256sum --check -; \
    else \
        ib="https://download2.interactivebrokers.com/installers/ibgateway/${IB_GATEWAY_CHANNEL}-standalone" \
        && gw_version="$(curl -fsSL "${ib}/version.json" | sed -n 's/.*"buildVersion" *: *"\([^"]*\)".*/\1/p')" \
        && test -n "${gw_version}" \
        && echo "No installer store: installing IB's current ${IB_GATEWAY_CHANNEL} build, ${gw_version}" \
        && curl -fsSL -o installer.sh "${ib}/ibgateway-${IB_GATEWAY_CHANNEL}-standalone-linux-x64.sh" \
        && sha256sum installer.sh; \
    fi \
    && chmod a+x ./installer.sh \
    # Install IB Gateway
    && if [ "${TARGETARCH}" = "arm64" ]; then \
        app_java_home=/usr/local/zulu17 ./installer.sh -q -dir /root/Jts/ibgateway/${gw_version}; \
    else \
        ./installer.sh -q -dir /root/Jts/ibgateway/${gw_version}; \
    fi \
    # The installer names no version until it runs: confirm the installed
    # build is the one expected, from install4j's own record.
    && if ! grep -q "Build ${gw_version} " /root/Jts/ibgateway/${gw_version}/.install4j/i4jparams.conf; then \
        echo "The installer for ${gw_version} installed something else:" >&2; \
        grep -o 'Build [^"]*' /root/Jts/ibgateway/${gw_version}/.install4j/i4jparams.conf >&2 || true; \
        exit 1; \
    fi \
    # Record the installed build. Without a store it can differ from
    # IB_GATEWAY_VERSION; the payload check and the entrypoint read this.
    && echo "${gw_version}" > /root/Jts/gateway-version

# jts.ini template (ibctl's version, includes ReadOnlyApi=no)
COPY docker/jts.ini.tmpl /root/Jts/jts.ini.tmpl

##############################################################################
# Stage 2a: Download pre-built ibctl binaries (if IBCTL_VERSION is set)
##############################################################################
FROM ubuntu:24.04 AS prebuilt-downloader
ARG IBCTL_VERSION
ARG DEBIAN_FRONTEND=noninteractive
# Two-phase mirror setup (see Stage 1 for rationale)
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends ca-certificates \
    && sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends curl
RUN mkdir -p /prebuilt \
    && if [ -n "${IBCTL_VERSION}" ]; then \
        echo "Downloading pre-built ibctl ${IBCTL_VERSION}" \
        && curl -sL -o /prebuilt/ibctl "https://github.com/Lcstyle/ibctl/releases/download/${IBCTL_VERSION}/ibctl" \
        && curl -sL -o /prebuilt/ibctl-agent.jar "https://github.com/Lcstyle/ibctl/releases/download/${IBCTL_VERSION}/ibctl-agent.jar" \
        && chmod +x /prebuilt/ibctl; \
    else \
        echo "No IBCTL_VERSION — will build from source" \
        && touch /prebuilt/.build-from-source; \
    fi

##############################################################################
# Stage 2b: Build Rust binary from source (fallback)
##############################################################################
FROM rust:1.97-bookworm AS rust-builder
ARG IBCTL_BUILD_VERSION=""
COPY Cargo.toml Cargo.lock /build/
COPY .cargo/ /build/.cargo/
COPY ibctl/ /build/ibctl/
# .build-version is written by CI's compute-version step with the output of
# `git describe --tags --always` — e.g. `v1.1.0-65-g7009dde`. The file is
# also committed with placeholder content "dev" so local `docker build .`
# without CI still works.
COPY .build-version /build/.build-version
WORKDIR /build
# Use thin LTO for Docker source builds (fast). Release workflow uses fat LTO.
# IBCTL_BUILD_VERSION is read by build.rs to embed the version string.
# Priority: explicit --build-arg > .build-version file > "unknown".
# Cargo registry + git + build cache mounts survive across CI runs so cargo
# doesn't re-download all crates or re-compile untouched dependencies.
RUN --mount=type=cache,target=/usr/local/cargo/registry,sharing=locked \
    --mount=type=cache,target=/usr/local/cargo/git,sharing=locked \
    --mount=type=cache,target=/build/target,sharing=locked \
    sed -i 's/lto = "fat"/lto = "thin"/' /build/.cargo/config.toml \
    && sed -i 's/codegen-units = 1/codegen-units = 16/' /build/.cargo/config.toml \
    && VERSION="${IBCTL_BUILD_VERSION:-$(cat .build-version 2>/dev/null || echo unknown)}" \
    && echo "Building with IBCTL_BUILD_VERSION=$VERSION" \
    && IBCTL_BUILD_VERSION="$VERSION" cargo build --release \
    && strip target/release/ibctl \
    # Cache mount at /build/target is ephemeral after this RUN exits — copy
    # the built binary to a regular path (/build/) so COPY --from can pick it
    # up in the final stage.
    && cp target/release/ibctl /build/ibctl-release

##############################################################################
# Stage 2c: Build Java agent from source (fallback)
##############################################################################
FROM eclipse-temurin:17-jdk-jammy AS java-builder
COPY agent/src/ /build/agent/src/
COPY agent/pom.xml /build/agent/pom.xml
WORKDIR /build/agent
RUN mkdir -p target/classes \
    && javac --release 17 -d target/classes src/main/java/ibctl/agent/*.java \
    && jar cfm target/ibctl-agent.jar src/main/resources/META-INF/MANIFEST.MF -C target/classes .

##############################################################################
# Stage 3: Production image
# Same base + packages as gnzsnz, minus IBC
##############################################################################
FROM ubuntu:24.04

ARG IB_GATEWAY_VERSION
ARG IB_GATEWAY_CHANNEL
ARG USER_ID=1000
ARG USER_GID=1000
ARG DEBIAN_FRONTEND=noninteractive

# Environment (matching gnzsnz conventions)
ENV HOME=/home/ibgateway \
    IB_GATEWAY_VERSION=${IB_GATEWAY_VERSION} \
    IB_GATEWAY_CHANNEL=${IB_GATEWAY_CHANNEL} \
    TWS_MAJOR_VRSN=${IB_GATEWAY_VERSION} \
    TWS_PATH=/home/ibgateway/Jts \
    GATEWAY_OR_TWS=gateway \
    NO_AT_BRIDGE=1

# Copy Gateway + JRE from setup stage (same as gnzsnz)
COPY --from=setup /usr/local/ /usr/local/
COPY --from=setup /root/Jts /home/ibgateway/Jts

# Install runtime packages + Python for dashboard.
# Two-phase mirror: archive.ubuntu.com HTTP (base image default) → install
# ca-certificates → rewrite HTTP → HTTPS → install the rest. See Stage 1
# for rationale on avoiding regional-mirror single points of failure.
# Apt cache mounts persist downloaded .deb files across CI runs so subsequent
# builds skip the re-download of the ~150 MB worth of runtime packages.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
    && apt-get update -y \
    && apt-get install --no-install-recommends --yes ca-certificates \
    && sed -i 's|http://archive.ubuntu.com|https://archive.ubuntu.com|g; s|http://security.ubuntu.com|https://security.ubuntu.com|g' /etc/apt/sources.list.d/ubuntu.sources \
    && apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends --yes \
        gettext-base socat xvfb x11vnc sshpass openssh-client telnet iputils-ping \
        python3 websockify curl \
    # Remove default ubuntu user if present
    && if id ubuntu 2>/dev/null; then userdel -rf ubuntu; fi \
    # Create ibgateway user (matching gnzsnz)
    && groupadd --gid ${USER_GID} ibgateway \
    && useradd -ms /bin/bash --uid ${USER_ID} --gid ${USER_GID} ibgateway \
    && mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix \
    && mkdir -p /opt/ibctl \
    && mkdir -p /opt/ibctl/persist/config \
    && mkdir -p /opt/ibctl/persist/logs \
    && mkdir -p /run/ibctl && chmod 700 /run/ibctl

# Install dashboard Python dependencies via uv (10-50× faster than pip).
# COPY --from the official uv image — skips the HOME-sensitive install
# script. Pinning to the 0.11 minor track: patches come in, breaking
# changes don't.
#
# `uv sync --frozen --no-dev` installs the exact versions in uv.lock — no
# resolver work, no version float. `--frozen` fails loud if the lockfile
# drifts from pyproject.toml, so a stale lock caught in CI instead of
# shipping. The venv is auto-created at .venv inside the working dir.
# `--no-dev` skips the [dependency-groups] dev group (PEP 735) — pytest,
# coverage, pytest-asyncio — production only.
#
# Layer ordering: uv install runs BEFORE the binary copy so it stays cached
# across commits that only change Rust/Java code (every commit changes
# build.rs's embedded version, invalidating the binaries; Python deps
# almost never change).
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /usr/local/bin/uv
COPY dashboard/pyproject.toml dashboard/uv.lock dashboard/.python-version /opt/ibctl/dashboard/
WORKDIR /opt/ibctl/dashboard
# The dashboard runs on uv's managed CPython (the version in .python-version),
# installed under /opt/python. Ubuntu's python3 stays only for websockify and
# one small entrypoint helper.
ENV UV_PYTHON_INSTALL_DIR=/opt/python
RUN --mount=type=cache,target=/root/.cache/uv,sharing=locked \
    uv sync --frozen --no-dev --managed-python \
    && .venv/bin/python -c 'import sys; v = open(".python-version").read().strip(); assert "%d.%d" % sys.version_info[:2] == v, (sys.version, v)' \
    && chmod -R a+rX /opt/python \
    # uv is build-only — drop it from the final image to keep size down
    && rm -f /usr/local/bin/uv
WORKDIR /

# Copy ibctl binaries — prefer pre-built, fall back to source
COPY --from=prebuilt-downloader /prebuilt/ /tmp/prebuilt/
COPY --from=rust-builder /build/ibctl-release /tmp/source/ibctl
COPY --from=java-builder /build/agent/target/ibctl-agent.jar /tmp/source/ibctl-agent.jar
RUN if [ -f /tmp/prebuilt/ibctl ]; then \
        echo "Using pre-built ibctl release" \
        && cp /tmp/prebuilt/ibctl /opt/ibctl/ibctl \
        && cp /tmp/prebuilt/ibctl-agent.jar /opt/ibctl/ibctl-agent.jar; \
    else \
        echo "Using source-built ibctl" \
        && cp /tmp/source/ibctl /opt/ibctl/ibctl \
        && cp /tmp/source/ibctl-agent.jar /opt/ibctl/ibctl-agent.jar; \
    fi && rm -rf /tmp/prebuilt /tmp/source

# Copy dashboard source
COPY dashboard/app /opt/ibctl/dashboard/app

# Copy ibctl config and entrypoint
COPY docker/entrypoint.sh /opt/ibctl/entrypoint.sh
COPY docker/ibctl.toml /opt/ibctl/ibctl.toml
RUN chmod +x /opt/ibctl/ibctl /opt/ibctl/entrypoint.sh \
    && chown -R ibgateway:ibgateway /home/ibgateway /opt/ibctl /run/ibctl

# The image must prove it can launch the Gateway it carries before it can
# ship. This is the resolution a real launch uses (install folder,
# jars, vmoptions, the Gateway's own Java), plus `java -version` and the agent
# jar. The 10.50.1f installer moved its Java and the image crash-looped in
# production; with this, a layout change fails the build instead.
RUN gw_version="$(cat /home/ibgateway/Jts/gateway-version)" \
    && IB_GATEWAY_VERSION="${gw_version}" TWS_MAJOR_VRSN="${gw_version}" \
       /opt/ibctl/ibctl preflight --payload --config /opt/ibctl/ibctl.toml

USER ${USER_ID}:${USER_GID}
WORKDIR /home/ibgateway

# No Docker HEALTHCHECK — ibctl manages its own lifecycle, liveness checks,
# and notifications. A Docker healthcheck with restart: unless-stopped is
# destructive: it kills the container during legitimate 2FA waits, destroying
# authenticated sessions and forcing re-authentication.

ENTRYPOINT ["/opt/ibctl/entrypoint.sh"]

# Mnemonic build badge: the SOURCE_HEX (short commit SHA) is passed as a
# build-arg by CI and baked into the image so the badge mnemonic reflects
# code identity. The BUILD_TIME_* values are computed by entrypoint.sh at
# container start — that gives the operator "when did this container start"
# (deploy time) instead of "when was the layer built", which is the more
# useful signal for at-a-glance change detection.
ARG SOURCE_HEX=""
ENV IBCTL_BUILD_SHA=$SOURCE_HEX
# LABEL parallel to the ENV so `docker inspect --format` can read the
# SHA without needing `docker exec` (race-free at container-start,
# and works even when the container has crashed).
LABEL IBCTL_BUILD_SHA=$SOURCE_HEX

LABEL org.opencontainers.image.source=https://github.com/Lcstyle/ibctl
LABEL org.opencontainers.image.description="IBC replacement for automated IB Gateway/TWS login and session management"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version=${IB_GATEWAY_VERSION}
