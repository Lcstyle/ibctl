# ibctl — IBC replacement for IB Gateway/TWS automation
# Self-contained build following gnzsnz/ib-gateway-docker's proven process,
# but without IBC. ibctl replaces it entirely.
#
# Two build modes:
#   Fast (pre-built release):
#     docker build --build-arg IBCTL_VERSION=v0.1.0 -t ibctl .
#   From source (no release available):
#     docker build -t ibctl .

ARG IB_GATEWAY_VERSION=10.45.1b
ARG IB_GATEWAY_CHANNEL=latest
ARG IBCTL_VERSION=""

##############################################################################
# Stage 1: Setup — download and install IB Gateway
# Follows gnzsnz/ib-gateway-docker's exact process (minus IBC)
##############################################################################
FROM ubuntu:24.04 AS setup

ARG IB_GATEWAY_VERSION
ARG IB_GATEWAY_CHANNEL
ARG DEBIAN_FRONTEND=noninteractive
ARG IB_GATEWAY_FILE="ibgateway-${IB_GATEWAY_VERSION}-standalone-linux-x64.sh"
ARG IB_GATEWAY_REPO="https://github.com/gnzsnz/ib-gateway-docker"
ARG IB_GATEWAY_URL="${IB_GATEWAY_REPO}/releases/download/ibgateway-${IB_GATEWAY_CHANNEL}%40${IB_GATEWAY_VERSION}/${IB_GATEWAY_FILE}"
# aarch64 JDK (only used on ARM)
ARG ZULU_NAME=zulu17.60.17-ca-fx-jre17.0.16-linux_aarch64
ARG ZULU_FILE=${ZULU_NAME}.tar.gz
ARG ZULU_URL=https://cdn.azul.com/zulu/bin/${ZULU_FILE}

WORKDIR /tmp/setup

RUN apt-get update -y \
    && apt-get install --no-install-recommends --yes curl ca-certificates \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    # aarch64: download Zulu JDK
    && if [ "$(uname -m)" = "aarch64" ]; then \
        curl -sSLO ${ZULU_URL} && \
        tar -xzf ${ZULU_FILE} -C /usr/local/ && \
        ln -s /usr/local/${ZULU_NAME} /usr/local/zulu17; \
    fi \
    # Download and verify IB Gateway installer
    && curl -sSOL ${IB_GATEWAY_URL} \
    && curl -sSOL ${IB_GATEWAY_URL}.sha256 \
    && sha256sum --check ./${IB_GATEWAY_FILE}.sha256 \
    && chmod a+x ./${IB_GATEWAY_FILE} \
    # Install IB Gateway
    && if [ "$(uname -m)" = "aarch64" ]; then \
        app_java_home=/usr/local/zulu17 ./${IB_GATEWAY_FILE} -q -dir /root/Jts/ibgateway/${IB_GATEWAY_VERSION}; \
    else \
        ./${IB_GATEWAY_FILE} -q -dir /root/Jts/ibgateway/${IB_GATEWAY_VERSION}; \
    fi

# jts.ini template (ibctl's version, includes ReadOnlyApi=no)
COPY docker/jts.ini.tmpl /root/Jts/jts.ini.tmpl

##############################################################################
# Stage 2a: Download pre-built ibctl binaries (if IBCTL_VERSION is set)
##############################################################################
FROM ubuntu:24.04 AS prebuilt-downloader
ARG IBCTL_VERSION
RUN apt-get update -qq \
    && apt-get install -y -qq --no-install-recommends curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
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
FROM rust:1.83-bookworm AS rust-builder
COPY Cargo.toml Cargo.lock /build/
COPY .cargo/ /build/.cargo/
COPY ibctl/ /build/ibctl/
WORKDIR /build
# Use thin LTO for Docker source builds (fast). Release workflow uses fat LTO.
RUN sed -i 's/lto = "fat"/lto = "thin"/' /build/.cargo/config.toml \
    && sed -i 's/codegen-units = 1/codegen-units = 16/' /build/.cargo/config.toml \
    && cargo build --release && strip target/release/ibctl

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
ARG USER_ID=1000
ARG USER_GID=1000
ARG DEBIAN_FRONTEND=noninteractive

# Environment (matching gnzsnz conventions)
ENV HOME=/home/ibgateway \
    IB_GATEWAY_VERSION=${IB_GATEWAY_VERSION} \
    TWS_MAJOR_VRSN=${IB_GATEWAY_VERSION} \
    TWS_PATH=/home/ibgateway/Jts \
    GATEWAY_OR_TWS=gateway \
    NO_AT_BRIDGE=1

# Copy Gateway + JRE from setup stage (same as gnzsnz)
COPY --from=setup /usr/local/ /usr/local/
COPY --from=setup /root/Jts /home/ibgateway/Jts

# Install runtime packages (same as gnzsnz, minus IBC deps)
RUN apt-get update -y \
    && apt-get upgrade -y \
    && apt-get install --no-install-recommends --yes \
        gettext-base socat xvfb x11vnc sshpass openssh-client telnet \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    # Remove default ubuntu user if present
    && if id ubuntu 2>/dev/null; then userdel -rf ubuntu; fi \
    # Create ibgateway user (matching gnzsnz)
    && groupadd --gid ${USER_GID} ibgateway \
    && useradd -ms /bin/bash --uid ${USER_ID} --gid ${USER_GID} ibgateway \
    && mkdir -p /tmp/.X11-unix && chmod 1777 /tmp/.X11-unix \
    && mkdir -p /opt/ibctl \
    && mkdir -p /run/ibctl && chmod 700 /run/ibctl

# Copy ibctl binaries — prefer pre-built, fall back to source
COPY --from=prebuilt-downloader /prebuilt/ /tmp/prebuilt/
COPY --from=rust-builder /build/target/release/ibctl /tmp/source/ibctl
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

# Copy ibctl config and entrypoint
COPY docker/entrypoint.sh /opt/ibctl/entrypoint.sh
COPY docker/ibctl.toml /opt/ibctl/ibctl.toml
RUN chmod +x /opt/ibctl/ibctl /opt/ibctl/entrypoint.sh \
    && chown -R ibgateway:ibgateway /home/ibgateway /opt/ibctl /run/ibctl

USER ${USER_ID}:${USER_GID}
WORKDIR /home/ibgateway

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD bash -c 'echo STATUS > /dev/tcp/127.0.0.1/7462 && exit 0 || exit 1'

ENTRYPOINT ["/opt/ibctl/entrypoint.sh"]

LABEL org.opencontainers.image.source=https://github.com/Lcstyle/ibctl
LABEL org.opencontainers.image.description="IBC replacement for automated IB Gateway/TWS login and session management"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.version=${IB_GATEWAY_VERSION}
