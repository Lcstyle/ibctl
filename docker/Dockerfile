# ibctl test image — layers on gnzsnz/ib-gateway for Gateway + JDK
# Replaces IBC with ibctl binary + Java agent
FROM ghcr.io/gnzsnz/ib-gateway:latest

USER root

# Copy ibctl binary and agent jar
COPY ibctl /opt/ibctl/ibctl
COPY ibctl-agent.jar /opt/ibctl/ibctl-agent.jar
COPY ibctl.toml /opt/ibctl/ibctl.toml
COPY entrypoint.sh /opt/ibctl/entrypoint.sh
RUN chmod +x /opt/ibctl/ibctl /opt/ibctl/entrypoint.sh

USER ibgateway

ENTRYPOINT ["/opt/ibctl/entrypoint.sh"]
