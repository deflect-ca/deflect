# Copyright (c) 2021, eQualit.ie inc.
# All rights reserved.
#
# This source code is licensed under the BSD-style license found in the
# LICENSE file in the root directory of this source tree.

FROM golang:1.17-alpine

RUN apk update && apk upgrade && apk add git
# RUN go get -u github.com/githubnemo/CompileDaemon

RUN mkdir -p /opt/test-origin
RUN mkdir -p /opt/test-origin/static
COPY ./test-origin.go /opt/test-origin/
COPY ./go.mod /opt/test-origin/
COPY ./static/deflectlogo_RED.png /opt/test-origin/static/

EXPOSE 8080

WORKDIR /opt/test-origin
RUN go get -u github.com/gin-gonic/gin
RUN go build
RUN export GIN_MODE=release
CMD ["./test-origin"]
# ENTRYPOINT CompileDaemon --build="go build test-origin.go" --command="./test-origin"
