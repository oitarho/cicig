FROM alpine:3.22

RUN apk add --no-cache bash iproute2 iptables python3 wireguard-go wireguard-tools
COPY vpn/native_api.py /usr/local/bin/cicig-native-vpn
COPY scripts/apply-network-policies.sh /usr/local/bin/cicig-apply-network-policies
RUN chmod 0755 /usr/local/bin/cicig-native-vpn /usr/local/bin/cicig-apply-network-policies

ENTRYPOINT ["python3", "/usr/local/bin/cicig-native-vpn"]
