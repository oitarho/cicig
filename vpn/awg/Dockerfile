FROM amneziavpn/amneziawg-go@sha256:4450928744b051589bb3ba5cf6dd0cd8d7dc470b9432dc32d03d5ff5ede11b7a

RUN apk add --no-cache python3

COPY vpn/native_api.py /usr/local/bin/cicig-native-vpn
COPY scripts/apply-network-policies.sh /usr/local/bin/cicig-apply-network-policies
RUN chmod 0755 /usr/local/bin/cicig-native-vpn /usr/local/bin/cicig-apply-network-policies

ENV WG_QUICK_USERSPACE_IMPLEMENTATION=amneziawg-go
ENTRYPOINT ["python3", "/usr/local/bin/cicig-native-vpn"]
