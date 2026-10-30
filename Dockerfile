# syntax=docker/dockerfile:1

FROM golang:1.27.2 AS build

WORKDIR /src

COPY go.mod ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal

RUN mkdir -p /out/logs && chown 65532:65532 /out/logs

RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /out/redishoneypot \
    ./cmd/redishoneypot

FROM scratch

COPY --from=build /out/redishoneypot /redishoneypot
COPY --from=build --chown=65532:65532 /out/logs /var/log/redishoneypot

# The Compose file gives the container 256 MiB; the GC works harder before Go
# reaches it.
ENV GOMEMLIMIT=200MiB

USER 65532:65532
EXPOSE 6379/tcp
VOLUME ["/var/log/redishoneypot"]
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/redishoneypot", "healthcheck", "-addr", "127.0.0.1:6379", "-timeout", "2s"]

ENTRYPOINT ["/redishoneypot"]
CMD ["-addr", "0.0.0.0:6379", "-proto", "tcp", "-profile", "redis74", "-max-clients", "128", "-max-command-bytes", "1048576", "-max-data-bytes", "33554432", "-max-reply-bytes", "33554432", "-log-file", "/var/log/redishoneypot/redishoneypot.log"]
