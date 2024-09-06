# syntax=docker/dockerfile:1.2
FROM alpine:3.20

ARG TARGETOS
ARG TARGETARCH

ARG STOPNIK_VERSION=dev

RUN apk add --no-cache --no-progress ca-certificates tzdata

COPY ./dist/stopnik.$STOPNIK_VERSION-$TARGETOS-$TARGETARCH /stopnik

EXPOSE 8080
EXPOSE 8081

STOPSIGNAL SIGTERM

ENTRYPOINT ["/stopnik"]