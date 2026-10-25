# syntax=docker/dockerfile:1.2
FROM gcr.io/distroless/static-debian12

ARG TARGETPLATFORM
COPY --chmod=755 ./bin/${TARGETPLATFORM}/stopnik /stopnik

EXPOSE 8080
EXPOSE 8081

STOPSIGNAL SIGTERM

ENTRYPOINT ["/stopnik"]