# syntax=docker/dockerfile:1.2
FROM alpine:3.20

RUN apk add --no-cache --no-progress ca-certificates tzdata
RUN touch /config.yml

COPY ./dist/stopnik /

EXPOSE 8080
EXPOSE 8081

ENTRYPOINT ["/stopnik"]