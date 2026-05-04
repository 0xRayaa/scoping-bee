FROM alpine:3.20

RUN apk add --no-cache \
    bash \
    git \
    nodejs \
    npm \
    python3 \
    bc \
    coreutils \
    findutils \
    grep \
    sed

# Allow git to inspect the mounted volume (owned by host user)
RUN git config --global --add safe.directory /scan

# Copy the scanner
COPY scripts/threat_intel_scan.sh /usr/local/bin/threat_intel_scan.sh
RUN chmod +x /usr/local/bin/threat_intel_scan.sh

ENTRYPOINT ["/usr/local/bin/threat_intel_scan.sh"]
CMD ["/scan"]
