
# From repo root - docker build -f kubernetes/Dockerfile -t owlsm:local build/owlsm
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY . /opt/owlsm

ENTRYPOINT ["/opt/owlsm/bin/owlsm"]
CMD ["-c", "/etc/owlsm/config.json"]
