FROM golang:1-alpine3.19 AS builder

ARG COMMIT_HASH
ENV COMMIT_HASH=${COMMIT_HASH}

RUN apk add --no-cache bash git ca-certificates build-base su-exec olm-dev

COPY . /build
WORKDIR /build
RUN ./build.sh

FROM alpine:3.19

ENV UID=1337 \
    GID=1337

RUN apk add --no-cache ffmpeg su-exec ca-certificates olm bash jq yq curl

COPY --from=builder /build/beeper-imessage /usr/bin/beeper-imessage
COPY --from=builder /build/example-config.yaml /opt/beeper-imessage/example-config.yaml
COPY --from=builder /build/docker-run.sh /docker-run.sh
VOLUME /data

CMD ["/docker-run.sh"]
