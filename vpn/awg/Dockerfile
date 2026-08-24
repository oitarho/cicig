FROM ghcr.io/yokitoki/awg-easy:latest

RUN apk add --no-cache iproute2
COPY scripts/apply-network-policies.sh /usr/local/bin/cicig-apply-network-policies
RUN chmod 0755 /usr/local/bin/cicig-apply-network-policies

